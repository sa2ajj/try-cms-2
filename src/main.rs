use anyhow::Context as _;

use cryptographic_message_syntax::{
    SignedData,
    SignerInfo,
};

use x509_certificate::{
    CapturedX509Certificate,
};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os();
    args
        .next()
        .context("i do not know who i am :(")?;
    let root = args
        .next()
        .context("unable to get root certificate name")?;
    let data = args
        .next()
        .context("unable to get data file name")?;
    let signer = args
        .next()
        .context("unable to get original signer certificate name")?;

    let data_sig = std::path::Path::new(&data)
        .with_extension("sig");

    println!("root: {:?}", root);
    println!("data: {:?}", data);
    println!("data_sig: {:?}", data_sig);
    println!("origin signer: {:?}", signer);

    let root = std::fs::read(&root)
        .context("unable to read root certificate")?;
    let root = CapturedX509Certificate::from_pem(&root)
        .context("invalid root certificate?")?;
    root.verify_signed_by_certificate(&root)
        .context("unable to verify that root CA is the root CA")?;

    let data = std::fs::read(&data)
        .context("unable to read data")?;

    let data_sig = std::fs::read(&data_sig)
        .context("unable to read signature")?;

    let signer = std::fs::read(signer)
        .context("unable to read signer certificate")?;
    let signer = CapturedX509Certificate::from_pem(&signer)
        .context("invalid signer certificate?")?;

    signer.verify_signed_by_certificate(&root)
        .context("signer certificate is not signed by trusted root")?;

    println!("{:#?}", &signer);

    let signed_data = SignedData::parse_ber(&data_sig)
        .context("unable to parse signature")?;

    let certs: Vec<&CapturedX509Certificate> = signed_data.certificates().collect();

    if certs.len() != 1 {
        return Err(anyhow::Error::msg(format!("wrong number of certificates: expected 1, got {}", certs.len())))
    }

    println!("{:#?}", certs[0]);

    certs[0].verify_signed_by_certificate(&root)
        .context("included certificate is not signed by trusted root")?;

    let signers: Vec<&SignerInfo> = signed_data.signers().collect();

    if signers.len() != 1 {
        return Err(anyhow::Error::msg(format!("wrong number of signers: expected 1, got {}", signers.len())))
    };

    let signer = signers[0];

    Ok(signer.verify_signature_with_signed_data_and_content(
        &signed_data,
        &data,
    )?)
}
