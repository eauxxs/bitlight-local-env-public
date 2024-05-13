use std::{collections::HashMap, env, str::FromStr};

use assert_cmd::Command;
use bdk::{
    bitcoin::bip32::{DerivationPath, KeySource},
    blockchain::EsploraBlockchain,
    database::{BatchDatabase, MemoryDatabase},
    keys::{DerivableKey, DescriptorKey, ExtendedKey},
    miniscript::Segwitv0,
    SignOptions, SyncOptions,
};
use bp::dbc::Method;
use bpstd::{Wpkh, XpubDerivable};
use bpwallet::{Runtime, WalletUtxo};
use dotenv::dotenv;
use esplora::Builder;
use psbt::Psbt;
use rgb::{
    containers::{BuilderSeal, Transfer, UniversalFile, ValidContract},
    invoice::{Beneficiary, RgbInvoice, RgbInvoiceBuilder, XChainNet},
    pay::WalletProvider,
    persistence::{MemIndex, MemStash, MemState},
    AnyResolver, ContractId, DescriptorRgb, GenesisSeal, GraphSeal, RgbDescr, RgbKeychain,
    StateType, TapretKey, TransferParams, XChain,
};
use rgbstd::persistence::Stock;
use strict_encoding::FieldName;
use strict_types::StrictVal;

fn create_wallet(xpub: &str, ty: DescType) -> Runtime<RgbDescr> {
    let n = bpstd::Network::Regtest;
    let xpub = XpubDerivable::from_str(xpub).unwrap();
    let desc: RgbDescr<XpubDerivable> = match ty {
        DescType::Taproot => RgbDescr::TapretKey(TapretKey::new_unfunded(xpub)),
        DescType::Segwitv0 => RgbDescr::Wpkh(Wpkh::from(xpub)),
    };
    Runtime::new_standard(desc, n)
}

fn create_stock() -> Stock {
    let mut s = Stock::<MemStash, MemState, MemIndex>::default();

    let UniversalFile::Kit(kit) =
        UniversalFile::load_file("tests/NonInflatableAssets.rgb").unwrap()
    else {
        panic!("Failed to load the kit file");
    };

    let kit = kit.validate().unwrap();
    s.import_kit(kit).unwrap();
    s
}

fn create_contract(
    stock: &Stock,
    utxo: &WalletUtxo,
    method: Method,
    token_name: &str,
    amount: u64,
) -> ValidContract {
    let sch = stock.schemata().unwrap().next().unwrap();
    let schema_id = sch.id;
    let iface_id = sch.implements.first().unwrap().iface_id;

    let schema_ifaces = stock.schema(schema_id).unwrap();
    let iface_impl = schema_ifaces.get(iface_id).unwrap();

    let issur = sch.developer;
    let mut builder = stock.contract_builder(issur, schema_id, iface_id).unwrap();
    let types = builder.type_system().clone();

    let token_name = StrictVal::from(token_name);
    let globals: HashMap<&str, StrictVal> = [
        (
            "spec",
            StrictVal::map([
                ("ticker", token_name.clone()),
                ("name", token_name.clone()),
                ("details", token_name.clone()),
                ("precision", StrictVal::from(0_u8)),
            ]),
        ),
        ("issuedSupply", StrictVal::from(amount)),
        (
            "terms",
            StrictVal::map([
                ("text", StrictVal::from("TEXT")),
                ("media", StrictVal::none()),
            ]),
        ),
    ]
    .into();

    for (name, val) in globals {
        let state_type = iface_impl
            .global_state
            .iter()
            .find(|info| info.name.as_str() == name)
            .unwrap_or_else(|| panic!("unknown type name '{name}'"))
            .id;
        let sem_id = schema_ifaces
            .schema
            .global_types
            .get(&state_type)
            .expect("invalid schema implementation")
            .sem_id;
        let val = StrictVal::from(val.clone());
        let typed_val = types
            .typify(val, sem_id)
            .expect("global type doesn't match type definition");
        const U16: usize = u16::MAX as usize;
        let serialized = types
            .strict_serialize_type::<U16>(&typed_val)
            .expect("internal error");
        let field_name = FieldName::try_from(name.to_owned()).expect("invalid type name");
        builder = builder
            .add_global_state(field_name, serialized)
            .expect("invalid global state data");
    }

    let name = "assetOwner";
    let state_type = iface_impl
        .assignments
        .iter()
        .find(|info| info.name.as_str() == name)
        .expect("unknown type name")
        .id;
    let state_schema = schema_ifaces
        .schema
        .owned_types
        .get(&state_type)
        .expect("invalid schema implementation");
    let seal = GenesisSeal::new_random(method, utxo.outpoint.txid, utxo.outpoint.vout);
    let field_name = FieldName::try_from(name.to_owned()).expect("invalid type name");
    match state_schema.state_type() {
        StateType::Fungible => {
            let seal = BuilderSeal::Revealed(XChain::Bitcoin(seal));
            builder = builder
                .add_fungible_state(field_name, seal, amount)
                .expect("invalid global state data");
        }
        _ => unreachable!(),
    }

    builder.issue_contract().unwrap()
}

#[test]
fn test_transfer() {
    let mut w = repare_wallet(DescType::Taproot, DescType::Taproot, DescType::Taproot);
    let w_alice = &mut w.alice.rgb;
    let w_bob = &mut w.bob.rgb;
    let w_dave = &mut w.dave.rgb;
    let mut stock = create_stock();

    // alice_utxo
    let utxo = w_alice
        .all_utxos()
        .find(|u| RgbKeychain::contains_rgb(u.terminal.keychain))
        .unwrap();

    // issue contract A
    let c_rgb = create_contract(&stock, &utxo, Method::TapretFirst, "RGB", 1000);
    let c_rgb_id = c_rgb.contract_id();
    println!("contractid: {}", c_rgb_id);

    let mut any_resolver = AnyResolver::esplora_blocking(ESPLORA_URL).unwrap();
    stock.import_contract(c_rgb, &mut any_resolver).unwrap();

    // issue contract B
    let c_usdt = create_contract(&stock, &utxo, Method::TapretFirst, "USDT", 1000);
    let c_usdt_id = c_usdt.contract_id();
    println!("contractid: {}", c_usdt_id);
    stock.import_contract(c_usdt, &mut any_resolver).unwrap();

    // alice to bob
    {
        let invb = get_invoice(&mut stock, &w_bob, c_rgb_id, 10);
        let invbu = get_invoice(&mut stock, &w_bob, c_usdt_id, 10);
        let (rpsbt, _meta, _consignment) = w_alice
            .pay(
                &mut stock,
                &[invb, invbu],
                TransferParams::with(400_u32.into(), 0_u32.into()),
            )
            .unwrap();

        broad_psbt(&w.alice.bdk, &rpsbt);
        mint();
        w_alice.to_sync();
        accept_consign(&mut stock, _consignment);
        // w_bob.to_sync();
    }

    // bob to dave
    {
        let invd = get_invoice(&mut stock, &w_dave, c_rgb_id, 4);
        let invdu = get_invoice(&mut stock, &w_dave, c_usdt_id, 4);
        let (rpsbt, _meta, _consignment) = w_bob
            .pay(
                &mut stock,
                &[invd, invdu],
                TransferParams::with(400_u32.into(), 0_u32.into()),
            )
            .unwrap();

        broad_psbt(&w.bob.bdk, &rpsbt);
        mint();
        w_bob.to_sync();

        accept_consign(&mut stock, _consignment);
        // w.dave.rgb.to_sync();
    }

    // bob to dave
    {
        let invd = get_invoice(&mut stock, &w_dave, c_rgb_id, 1);
        let invdu = get_invoice(&mut stock, &w_dave, c_usdt_id, 1);
        let (rpsbt, _meta, _consignment) = w_bob
            .pay(
                &mut stock,
                &[invd, invdu],
                TransferParams::with(400_u32.into(), 0_u32.into()),
            )
            .unwrap();

        broad_psbt(&w.bob.bdk, &rpsbt);
        mint();
        w_bob.to_sync();

        accept_consign(&mut stock, _consignment);
        // w.dave.rgb.to_sync();
    }
    print_history(&stock, w_alice, w_bob, w_dave);
}

fn print_history(
    stock: &Stock,
    w_alice: &Runtime<RgbDescr>,
    w_bob: &Runtime<RgbDescr>,
    w_dave: &Runtime<RgbDescr>,
) {
    let iface_id = stock.ifaces().unwrap().next().unwrap().id;
    let contra = stock.contracts().unwrap();

    for cid in contra {
        let contract = stock.contract_iface(cid.id, iface_id).unwrap();
        println!("\nGlobal:");
        for global in &contract.iface.global_state {
            if let Ok(values) = contract.global(global.name.clone()) {
                for val in values {
                    println!("  {} := {}", global.name, val);
                }
            }
        }
        println!("\nOwned:");
        for owned in &contract.iface.assignments {
            println!("alice  {}:", owned.name);
            if let Ok(allocations) = contract.fungible(owned.name.clone(), w_alice.filter()) {
                for allocation in allocations {
                    println!(
                        "    amount={}, utxo={}, witness={} # owned by the wallet",
                        allocation.state, allocation.seal, allocation.witness
                    );
                }
            }
            println!("bob  {}:", owned.name);
            if let Ok(allocations) = contract.fungible(owned.name.clone(), &w_bob.filter()) {
                for allocation in allocations {
                    println!(
                        "    amount={}, utxo={}, witness={} # owned by the wallet",
                        allocation.state, allocation.seal, allocation.witness
                    );
                }
            }
            println!("dave  {}:", owned.name);
            if let Ok(allocations) = contract.fungible(owned.name.clone(), &w_dave.filter()) {
                for allocation in allocations {
                    println!(
                        "    amount={}, utxo={}, witness={} # owned by the wallet",
                        allocation.state, allocation.seal, allocation.witness
                    );
                }
            }
        }
    }
}

fn accept_consign(stock: &mut Stock, transfers: Vec<Transfer>) {
    let mut resolver = AnyResolver::esplora_blocking(ESPLORA_URL).unwrap();
    for transfer in transfers {
        resolver.add_terminals(&transfer);
        let valid = transfer
            .validate(&mut resolver, true)
            .map_err(|(status, _)| status)
            .unwrap();
        stock.accept_transfer(valid, &mut resolver).unwrap();
    }
}

fn broad_psbt(w: &bdk::Wallet<MemoryDatabase>, psbt: &Psbt) {
    use bdk::bitcoin::psbt::PartiallySignedTransaction;
    let mut p =
        PartiallySignedTransaction::from_str(psbt.to_base64_ver(psbt::PsbtVer::V0).as_str())
            .unwrap();

    let mut opts = SignOptions::default();
    opts.trust_witness_utxo = true;
    let finalized = w.sign(&mut p, opts).unwrap();
    assert!(finalized);

    let esplora = EsploraBlockchain::new(ESPLORA_URL, 10);
    esplora.broadcast(&p.extract_tx()).unwrap();
}

fn get_invoice(
    stock: &mut Stock,
    w: &Runtime<RgbDescr>,
    contract_id: ContractId,
    amount: u64,
) -> RgbInvoice {
    let iface_name = stock.ifaces().unwrap().next().unwrap().name;
    let utxo = w.all_utxos().next().unwrap();
    let seal = XChain::Bitcoin(GraphSeal::new_random(
        w.seal_close_method(),
        utxo.outpoint.txid,
        utxo.outpoint.vout,
    ));
    stock.store_secret_seal(seal.clone()).unwrap();

    let bene = Beneficiary::BlindedSeal(*seal.to_secret_seal().as_reduced_unsafe());
    RgbInvoiceBuilder::new(XChainNet::bitcoin(bpstd::Network::Regtest, bene))
        .set_contract(contract_id)
        .set_interface(iface_name)
        .set_amount_raw(amount)
        .finish()
}

const ESPLORA_URL: &str = "http://127.0.0.1:3002";
trait EsploraSync {
    fn to_sync(&mut self);
}

impl EsploraSync for Runtime<RgbDescr> {
    fn to_sync(&mut self) {
        let esplora_client = Builder::new(ESPLORA_URL).build_blocking().unwrap();
        self.sync(&esplora_client).unwrap();
    }
}

impl<D: BatchDatabase> EsploraSync for bdk::Wallet<D> {
    fn to_sync(&mut self) {
        let esplora = EsploraBlockchain::new(ESPLORA_URL, 10).with_concurrency(10);
        self.sync(&esplora, SyncOptions::default()).unwrap();
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum DescType {
    Segwitv0,
    Taproot,
}

impl DescType {
    fn with(self, xpub: &str) -> String {
        match self {
            DescType::Segwitv0 => format!("wpkh({})", xpub),
            DescType::Taproot => format!("tr({})", xpub),
        }
    }
}

struct Wlt {
    rgb: Runtime<RgbDescr>,
    bdk: bdk::Wallet<MemoryDatabase>,
}

struct TestWallet {
    alice: Wlt,
    bob: Wlt,
    dave: Wlt,
}

fn repare_wallet(alice: DescType, bob: DescType, dave: DescType) -> TestWallet {
    dotenv().ok();

    let alice_mne = env::var("ALICE_MNEMONIC").unwrap();
    let bob_mne = env::var("BOB_MNEMONIC").unwrap();
    let dave_mne = env::var("DAVE_MNEMONIC").unwrap();
    fn parse_mne(mne: String, ty: DescType) -> (String, String, String) {
        use bdk::keys::bip39::{Language, Mnemonic};
        let mne = Mnemonic::parse_in(Language::English, mne).unwrap();
        let xkey: ExtendedKey = mne.into_extended_key().unwrap();
        let xprv = xkey.into_xprv(bdk::bitcoin::Network::Regtest).unwrap();
        let secp = bdk::bitcoin::secp256k1::Secp256k1::new();
        const DPATH: &str = "m/86h/1h/0h";
        let path = DerivationPath::from_str(DPATH).unwrap();
        let derived_xprv = xprv.derive_priv(&secp, &path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), path);

        let derived_xprv_desc_key: DescriptorKey<Segwitv0> = derived_xprv
            .into_descriptor_key(Some(origin), DerivationPath::default())
            .unwrap();

        if let DescriptorKey::<Segwitv0>::Secret(desc_seckey, _, _) = derived_xprv_desc_key {
            let desc_pubkey = desc_seckey.to_public(&secp).unwrap();
            let xprv9 = desc_seckey.to_string().replace("/*", "/9/*");
            let xprv10 = desc_seckey.to_string().replace("/*", "/10/*");
            let xpub = desc_pubkey.to_string().replace("/*", "/<9;10>/*");
            (ty.with(&xprv9), ty.with(&xprv10), xpub)
        } else {
            panic!("Invalid key variant");
        }
    }

    let mut r = [alice_mne, bob_mne, dave_mne]
        .into_iter()
        .zip([alice, bob, dave])
        .map(|(mne, ty)| {
            let (xprv9, xprv10, xpub) = parse_mne(mne, ty);

            let mut rgb = create_wallet(&xpub, ty);
            rgb.to_sync();
            if !rgb
                .all_utxos()
                .any(|u| RgbKeychain::contains_rgb(u.terminal.keychain))
            {
                let addr = rgb.addresses(RgbKeychain::Rgb).next().unwrap().addr;
                let mut cmd = Command::cargo_bin("bitlight-local-env").unwrap();
                cmd.arg("send").arg(addr.to_string()).assert().success();
                mint();
                std::thread::sleep(std::time::Duration::from_secs(1));
                rgb.to_sync();
            }

            let mut bdk = bdk::Wallet::new(
                &xprv9,
                Some(&xprv10),
                bdk::bitcoin::Network::Regtest,
                MemoryDatabase::default(),
            )
            .unwrap();
            bdk.to_sync();
            // assert!(bdk.list_unspent().unwrap().len() > 0);
            Wlt { rgb, bdk }
        })
        .collect::<Vec<_>>();

    TestWallet {
        dave: r.pop().unwrap(),
        bob: r.pop().unwrap(),
        alice: r.pop().unwrap(),
    }
}

fn mint() {
    let mut cmd = Command::cargo_bin("bitlight-local-env").unwrap();
    cmd.arg("mint").arg("1").assert().success();
}
