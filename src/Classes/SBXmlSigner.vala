using Gee;
using GnuTLS;
using Xml;

[CCode (cname = "xmlsec_init")]
public extern int xmlsec_init();
[CCode (cname = "xmlsec_shutdown")]
public extern int xmlsec_shutdown();
[CCode (cname = "xmlsec_sign_file")]
public extern int xmlsec_sign_file(string tmpl_file, string key_file, string cert_file, out string signed_xml);

namespace SinticBolivia.Classes
{
    errordomain SBXmlSignerError {
        INVALID_IMPORT,
        INVALID_CERTIFICATE
    }
    public class SBXmlSigner
    {
        //*

        //*/
		public string private_key_filename;
		public string certificate;
		public string xml_root_node = "</Factura>";

        public SBXmlSigner()
        {

        }
        public SBXmlSigner.with_files(string cert, string key)
        {
            this.certificate = cert;
            this.private_key_filename = key;
        }
        public string? sign(string xml)
        {
            var now = new DateTime.now_local ();
            string xml_filename = "%s.xml".printf(now.to_unix().to_string());
            GLib.FileUtils.set_contents(xml_filename, xml);
            string signed_xml;
            xmlsec_init();
            xmlsec_sign_file(xml_filename, this.private_key_filename, this.certificate, out signed_xml);
            xmlsec_shutdown();
            GLib.FileUtils.unlink(xml_filename);
            return signed_xml;
        }
        public string? ___sign(string xml)
        {
            /*
			try
			{
				FileStream key_file = FileStream.open(this.private_key_filename, "r");
				string private_buffer = key_file.get_contents(null);
				GCrypt.Hash hash = new GCrypt.Hash(HashType.SHA256);
				hash.update(xml.data);
				uint8[] digest = hash.get_digest();

				GnuTLS.Datum pkDatum;
				var key = new GnuTLS.X509.PrivateKey.create();
				//key.import_x509_raw(private_buffer.data, KeyFormat.PEM, Keyflags.RSA);
				int res = key.import(ref pkDatum, GnuTLS.X509.CertificateFormat.PEM);
				if( res != 0 )
				    throw new SBXmlSignerError.INVALID_IMPORT("No se pudo importar la llave privada");
				uint8[] signature = key.sign(HashType.SHA256, digest);
				string signature_b64 = Base64.encode(signature.data);
				string signed_xml = xml.replace(
					this.xml_root_node,
					"<Signature>%s</Signature>%s".printf(signature_base64, this.xml_root_node)
				);
				return signed_xml;
			}
			catch(GLib.Error e)
			{
				stderr.printf("XML SIGNER ERROR: %s\n", e.message);
			}
			catch(SBXmlSignerError e)
			{
			    stderr.printf("XML SIGNER ERROR: %s\n", e.message);
			}
			*/
			return null;
		}
    }
}
