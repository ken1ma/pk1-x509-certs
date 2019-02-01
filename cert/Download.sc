#!/usr/bin/env amm

val wd = os.pwd

import scala.collection.JavaConverters._
import java.util.Base64
import java.security.cert.{CertificateFactory, X509Certificate, PKIXBuilderParameters, TrustAnchor}
import java.io.ByteArrayInputStream
import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import javax.security.auth.x500.X500Principal
import javax.net.ssl.{SSLContext, X509TrustManager, TrustManagerFactory, CertPathTrustManagerParameters}

def newHttpClientBuilder = HttpClient.newBuilder
		.followRedirects(HttpClient.Redirect.ALWAYS) // default NEVER
implicit val client = newHttpClientBuilder.build

/** @return (respBody, serverSslCerts) */
def download(uri: String)(implicit client: HttpClient) = {
	val req = HttpRequest.newBuilder.uri(new URI(uri)).build
	val resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray)
	if (resp.statusCode != 200)
		throw new Exception(s"statusCode = ${resp.statusCode}: $uri")
	(resp.body, Option(resp.sslSession.orElse(null)).map(_.getPeerCertificates.map(_.asInstanceOf[X509Certificate]))) // peer's own certificate first
}

val certFac = CertificateFactory.getInstance("X.509")

def decomposeRfc2253(text: String) = {
	// TODO: handle escape
	val comps = text.split(',')
	comps.map { comp =>
		val firstEq = comp.indexOf('=')
		comp.take(firstEq) -> comp.drop(firstEq + 1)
	}.toMap
}

def formatName(principal: X500Principal) = {
	val nameMap = decomposeRfc2253(principal.getName)
	Seq(
		nameMap.get("CN").map("CN=" + _),
		nameMap.get("OU").map("OU=" + _),
		nameMap.get("O" ).map("O="  + _),
	).flatten.mkString(",")
}

val pemBeginCert = "-----BEGIN CERTIFICATE-----"
val pemEndCert   = "-----END CERTIFICATE-----"
val pemBeginCertBin = pemBeginCert.getBytes("UTF-8")

def download(dst: String, uri: String, shouldBeSameAsExistingDst: Boolean = false)(implicit client: HttpClient): Array[Byte] = {
	println(s"$dst: $uri")
	val (content, _) = download(uri)

	val der = {
		if (content.startsWith(pemBeginCertBin)) {
			val rawLines = scala.io.Source.fromBytes(content, "UTF-8").getLines.toList
			val lines = rawLines.take(rawLines.lastIndexWhere(_.nonEmpty) + 1) // remove trailing empty lines
			require(lines.head == pemBeginCert, lines.head)
			require(lines.last == pemEndCert, lines.last)
			Base64.getDecoder.decode(lines.drop(1).dropRight(1).mkString)

		} else
			content
	}

	if (shouldBeSameAsExistingDst) {
		if (!os.read.bytes(wd / os.RelPath(s"$dst.cer")).sameElements(der))
			throw new Exception(s"$uri: does not match $dst")
	} else
		write(dst, der)

	der
}

def toX509Certificate(der: Array[Byte]) =
		certFac.generateCertificate(new ByteArrayInputStream(der)).asInstanceOf[X509Certificate] // handle both DER and PEM

def write(dst: String, der: Array[Byte], printDst: Boolean = false) {
	val indent = {
		if (printDst) {
			println(s"\t$dst")
			"\t\t"
		} else
			"\t"
	}
	os.write.over(wd / os.RelPath(s"$dst.cer"), der, createFolders = true)

	val cert = toX509Certificate(der)
	val subject = cert.getSubjectX500Principal
	val issuer = cert.getIssuerX500Principal
	if (subject == issuer)
		println(s"${indent}selfSigned: ${formatName(subject)}")
	else {
		println(s"${indent}subject:    ${formatName(subject)}")
		println(s"${indent}issuer:     ${formatName(issuer)}")
	}
}

def downloadSslCerts(uri: String, f: Array[X509Certificate] => Unit)(implicit client: HttpClient) {
	println(uri)
	// TODO: does Certificate.getEncoded keep the exact bynary? (probably yes since otherwise the hash would change)
	// alternative? "openssl s_client -showcerts -connect www.example.com:443 < /dev/null | openssl x509 -outform DER"
	val (_, certs) = download(uri)
	f(certs.get)
}

// GlobalSign Root Certificates
// https://support.globalsign.com/customer/portal/articles/1426602-globalsign-root-certificates
download("GlobalSign/R1", "https://secure.globalsign.net/cacert/Root-R1.crt")
download("GlobalSign/R3", "https://secure.globalsign.net/cacert/Root-R3.crt")
val globalSignR6 = download("GlobalSign/R6", "https://secure.globalsign.net/cacert/root-r6.crt")
download("GlobalSign/R5", "https://secure.globalsign.net/cacert/Root-R5.crt")

// Does my browser trust this certificate?
downloadSslCerts("https://valid.r1.roots.globalsign.com/", certs => {
	require(certs.length == 2, s"certs.length = ${certs.length}")
	write("GlobalSign/R1/OrganizationSSL-G3/valid.r1.roots.globalsign.com", certs(0).getEncoded, true)
	write("GlobalSign/R1/OrganizationSSL-G3", certs(1).getEncoded, true)
})
downloadSslCerts("https://valid.r3.roots.globalsign.com/", certs => {
	require(certs.length == 2, s"certs.length = ${certs.length}")
	write("GlobalSign/R3/ExtendedSSL-G3/valid.r3.roots.globalsign.com", certs(0).getEncoded, true)
	write("GlobalSign/R3/ExtendedSSL-G3", certs(1).getEncoded, true)
})
val globalSignR6Client = newHttpClientBuilder
		.sslContext {
			val sslContext = SSLContext.getInstance("TLSv1.2") // Chrome 71 uses TLS 1.2 to the site as of 2019-01-19
			sslContext.init(null, {
				val trustManagerFac = TrustManagerFactory.getInstance("PKIX")
				val trustAnchors = Set(new TrustAnchor(toX509Certificate(globalSignR6), null)).asJava
				val pkixBuilderParameters = new PKIXBuilderParameters(trustAnchors, null)
				pkixBuilderParameters.setRevocationEnabled(false) // TODO: make this true avoiding "java.security.cert.CertPathValidatorException: Could not determine revocation status"
				trustManagerFac.init(new CertPathTrustManagerParameters(pkixBuilderParameters))
				trustManagerFac.getTrustManagers
			}, null)
			sslContext
		} .build
downloadSslCerts("https://valid.r6.roots.globalsign.com/", certs => {
	require(certs.length == 2, s"certs.length = ${certs.length}")
	write("GlobalSign/R6/Admin-G3/valid.r6.roots.globalsign.com", certs(0).getEncoded, true)
	write("GlobalSign/R6/Admin-G3", certs(1).getEncoded, true)
})(globalSignR6Client)
downloadSslCerts("https://valid.r5.roots.globalsign.com/", certs => {
	require(certs.length == 2, s"certs.length = ${certs.length}")
	write("GlobalSign/R5/Admin-CA2/valid.r5.roots.globalsign.com", certs(0).getEncoded, true)
	write("GlobalSign/R5/Admin-CA2", certs(1).getEncoded, true)
})

// GlobalSign Cross Certificates
// https://support.globalsign.com/customer/en/portal/articles/2960968-globalsign-cross-certificates
download("GlobalSign/R3withR1", "http://secure.globalsign.com/cacert/r1r3sha2cross2018.crt")
download("GlobalSign/R5withR3", "http://secure.globalsign.com/cacert/r3r5cross2018.crt")

// IntranetSSL Root & Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/2084405-intranetssl-root-intermediate-certificates
download("GlobalSign-IntranetSSL/R1/G3", "http://secure.globalsign.com/cacert/gsintranetsslg3.crt")
download("GlobalSign-IntranetSSL/R1", "http://secure.globalsign.com/cacert/gsnonpublicroot1.crt")
download("GlobalSign-IntranetSSL/R2/G3", "http://secure.globalsign.com/cacert/gsintranetsslsha256g3.crt")
download("GlobalSign-IntranetSSL/R2", "http://secure.globalsign.com/cacert/gsnonpublicroot2.crt")
download("GlobalSign-IntranetSSL/R3/G3", "http://secure.globalsign.com/cacert/gsintranetsslecc256g3.crt")
download("GlobalSign-IntranetSSL/R3", "http://secure.globalsign.com/cacert/gsnonpublicroot3.crt")

// AlphaSSL Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/1223298-alphassl-intermediate-certificates
download("GlobalSign/R1/AlphaSSL-G2", "https://secure.globalsign.com/cacert/gsalphasha2g2r1.crt")    // SHA-256 Orders (Default)
download("GlobalSign/R3/AlphaSSL-G2", "https://secure.globalsign.com/cacert/gsalphasha2g2r3.crt")    // SHA-256 Orders (Custom Chain)
// "SHA-256 Custom R3 Chain" download https://secure.alphassl.com/cacert/gsalphasha2g2.crt results in the same as "SHA-256 Orders (Default)"
download("GlobalSign/R3/AlphaSSL-G2-custom", "https://crt.sh/?d=443851") // SHA-256 Custom R3 Chain

// DomainSSL Intermediate Certificate
// https://support.globalsign.com/customer/en/portal/articles/1464460-domainssl-intermediate-certificate
download("GlobalSign/R1/DomainSSL-G2", "https://secure.globalsign.com/cacert/gsdomainvalsha2g2r1.crt")

// OrganizationSSL Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/1219303-organizationssl-intermediate-certificates
download("GlobalSign/R1/OrganizationSSL-G2", "https://secure.globalsign.com/cacert/gsorganizationvalsha2g2r1.crt")
download("GlobalSign/R3/OrganizationSSL-G2", "https://secure.globalsign.com/cacert/gsorganizationvalsha2g2r3.crt")

// ExtendedSSL Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/1223443-extendedssl-intermediate-certificates
download("GlobalSign/R3/ExtendedSSL-G3", "https://secure.globalsign.com/cacert/gsextendvalsha2g3r3.crt", shouldBeSameAsExistingDst = true)
download("GlobalSign/R2/ExtendedSSL-G2", "https://secure.globalsign.com/cacert/gsextendvalsha2g2r2.crt")

// CloudSSL Intermediate Certificate
download("GlobalSign/R1/CloudSSL-G3", "https://secure.globalsign.com/cacert/cloudsslsha2g3.crt")
download("GlobalSign/R3/CloudSSL-G3", "https://secure.globalsign.com/cacert/cloudsslsha2g3r3.crt")
download("GlobalSign/R3/CloudSSL-G3-ECC", "http://secure.globalsign.com/cacert/cloudssleccsha2g3.crt")

// Code Signing (Standard & EV) Intermediate Certificates
download("GlobalSign/R3/CodeSigningEV-G3", "https://secure.globalsign.com/cacert/gsextendcodesignsha2g3ocsp.crt")
download("GlobalSign/R3/CodeSigningEV-G2", "http://secure.globalsign.com/cacert/gsextendcodesignsha2g2.crt")
download("GlobalSign/R3/CodeSigningStandard-G3", "https://secure.globalsign.com/cacert/gscodesignsha2g3ocsp.crt")
download("GlobalSign/R3/CodeSigningStandard-G2", "https://secure.globalsign.com/cacert/gscodesignsha2g2.crt")
download("GlobalSign/R1/CodeSigningStandard-G3", "http://secure.globalsign.com/cacert/gscodesigng3ocsp.crt")
download("GlobalSign/R1/CodeSigningStandard-G2", "https://secure.globalsign.com/cacert/gscodesigng2.crt")

// AATL & Adobe CDS Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/2085904-aatl-adobe-cds-intermediate-certificates
// Adobe Approved Trust List
download("GlobalSign/R3/AATL-G2/CA-2", "http://secure.globalsign.com/cacert/gsaatl2sha2g2.crt")
download("GlobalSign/R3/AATL-G2", "http://secure.globalsign.com/cacert/gsaatlsha2g2.crt")
download("GlobalSign/R3/AATL-G2/CA-3", "http://secure.globalsign.com/cacert/gsaatl3sha2g2.crt")
// Certified Document Services
download("Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256/GlobalSign-CDS-SHA256", "http://secure.globalsign.com/cacert/gssha2adobe.der")
download("Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256", "http://secure.globalsign.com/cacert/gsprmsha2adobe.der")
download("Adobe/Adobe Root CA", "http://secure.globalsign.com/cacert/adoberoot.cer")

// PersonalSign Intermediate Certificates
// https://support.globalsign.com/customer/en/portal/articles/1211662-personalsign-intermediate-certificates
download("GlobalSign/R3/PersonalSign-G3-SHA256-1", "https://secure.globalsign.com/cacert/gspersonalsign1sha2g3ocsp.crt")
download("GlobalSign/R3/PersonalSign-G3-SHA256-2", "https://secure.globalsign.com/cacert/gspersonalsign2sha2g3ocsp.crt")
download("GlobalSign/R3/PersonalSign-G3-SHA256-3", "https://secure.globalsign.com/cacert/gspersonalsign3sha2g3ocsp.crt")
download("GlobalSign/R3/PersonalSign-G2-SHA256-1", "https://secure.globalsign.com/cacert/gspersonalsign1sha2g2.crt")
download("GlobalSign/R3/PersonalSign-G2-SHA256-2", "https://secure.globalsign.com/cacert/gspersonalsign2sha2g2.crt")
download("GlobalSign/R3/PersonalSign-G2-SHA256-3", "https://secure.globalsign.com/cacert/gspersonalsign3sha2g2.crt")
download("GlobalSign/R3/PersonalSign-G2-SHA256-Partners", "https://secure.globalsign.com/cacert/gspersonalsignptnrssha2g2.crt")
download("GlobalSign/R1/PersonalSign-G3-SHA1-1", "http://secure.globalsign.com/cacert/gspersonalsign1g3ocsp.crt")
download("GlobalSign/R1/PersonalSign-G3-SHA1-2", "http://secure.globalsign.com/cacert/gspersonalsign2g3ocsp.crt")
download("GlobalSign/R1/PersonalSign-G3-SHA1-3", "http://secure.globalsign.com/cacert/gspersonalsign3g3ocsp.crt")
download("GlobalSign/R1/PersonalSign-G2-SHA1-1", "https://secure.globalsign.com/cacert/gspersonalsign1g2.crt")
download("GlobalSign/R1/PersonalSign-G2-SHA1-2", "https://secure.globalsign.com/cacert/gspersonalsign2g2.crt")
download("GlobalSign/R1/PersonalSign-G2-SHA1-3", "https://secure.globalsign.com/cacert/gspersonalsign3g2.crt")
download("GlobalSign/R1/PersonalSign-G2-SHA1-Partners", "https://secure.globalsign.com/cacert/gspersonalsignptnrsg2.crt")

// GlobalSign Japan
// https://jp.globalsign.com/repository/
	// ルート証明書
		download("GlobalSign/R1", "https://jp.globalsign.com/repository/common/cer/rootcacert_r1.cer", shouldBeSameAsExistingDst = true)
		download("GlobalSign/R2", "https://jp.globalsign.com/repository/common/cer/rootcacert_r2.cer")
		download("GlobalSign/R3", "https://jp.globalsign.com/repository/common/cer/rootcacert_r3.cer", shouldBeSameAsExistingDst = true)
		download("GlobalSign-IntranetSSL/R1", "https://jp.globalsign.com/repository/common/cer/rootcaintrasslcert_sha1.cer", shouldBeSameAsExistingDst = true)
		download("GlobalSign-IntranetSSL/R2", "https://jp.globalsign.com/repository/common/cer/rootcaintrasslcert_sha2.cer", shouldBeSameAsExistingDst = true)
		download("GlobalSign-IntranetSSL/R3", "https://jp.globalsign.com/repository/common/cer/rootcaintrasslcert_eccsha2.cer", shouldBeSameAsExistingDst = true)
	// 中間CA証明書
		// クイック認証SSL
			download("GlobalSign/R1/DomainSSL-G2-SHA1", "https://jp.globalsign.com/repository/common/cer/dvcacert_v3.cer")
			download("GlobalSign/R1/DomainSSL-G2",      "https://jp.globalsign.com/repository/common/cer/gsdomainvalsha2g2.cer", shouldBeSameAsExistingDst = true)
		// 企業認証SSL
			download("GlobalSign/R1/OrganizationSSL-G2-SHA1", "https://jp.globalsign.com/repository/common/cer/ovcacert_v3.cer")
			download("GlobalSign/R1/OrganizationSSL-G2",      "https://jp.globalsign.com/repository/common/cer/gsorganizationvalsha2g2.cer", shouldBeSameAsExistingDst = true)
		// EV SSL
			download("GlobalSign/R2/ExtendedSSL-G2-SHA1", "https://jp.globalsign.com/repository/common/cer/evcacert_v3.cer")
			download("GlobalSign/R2/ExtendedSSL-G2",      "https://jp.globalsign.com/repository/common/cer/gsextendvalsha2g2.cer", shouldBeSameAsExistingDst = true)
		// クラウドSSL
			download("GlobalSign/R1/CloudSSL-G3", "https://jp.globalsign.com/repository/common/cer/cloudsslsha2g3.cer", shouldBeSameAsExistingDst = true)
		// イントラネットSSL
			download("GlobalSign-IntranetSSL/R1/G3", "https://jp.globalsign.com/repository/common/cer/intrasslcacert_sha1v2.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign-IntranetSSL/R2/G3", "https://jp.globalsign.com/repository/common/cer/intrasslcacert_sha2v2.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign-IntranetSSL/R3/G3", "https://jp.globalsign.com/repository/common/cer/intrasslcacert_eccsha2v2.cer", shouldBeSameAsExistingDst = true)
		// コードサイニング証明書
			download("GlobalSign/R1/CodeSigningStandard-G2", "https://jp.globalsign.com/repository/common/cer/cscacert_v2.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign/R3/CodeSigningStandard-G2-NoOCSP", "https://jp.globalsign.com/repository/common/cer/cscacert_v3.cer")
		// EVコードサイニング証明書
			download("GlobalSign/R3/CodeSigningEV-G2", "https://jp.globalsign.com/repository/common/cer/gsextendcodesignsha2g2.cer", shouldBeSameAsExistingDst = true)
		// PDF文書署名用証明書
			download("Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256",                       "https://jp.globalsign.com/repository/common/cer/cdscacert1.cer", shouldBeSameAsExistingDst = true)
			download("Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256/GlobalSign-CDS-SHA256", "https://jp.globalsign.com/repository/common/cer/cdscacert2.cer", shouldBeSameAsExistingDst = true)
		// 文書署名用証明書
			download("GlobalSign/R3/AATL-G2", "https://jp.globalsign.com/repository/common/cer/doccacert1.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign/R3/AATL-G2/CA-2", "https://jp.globalsign.com/repository/common/cer/doccacert2.cer", shouldBeSameAsExistingDst = true)
		// クライアント証明書
			download("GlobalSign/R1/PersonalSign-G3-SHA1-2-NoOCSP", "https://jp.globalsign.com/repository/common/cer/pscacert_v2-2.cer")
			download("GlobalSign/R3/PersonalSign-G3-SHA256-2-NoOCSP", "https://jp.globalsign.com/repository/common/cer/pscacert_v3-2.cer")
		// TA/TSA
			download("GlobalSign/R1/Timestamping-G2-SHA1", "https://jp.globalsign.com/repository/common/cer/TimestampingCA_v2.cer")
			download("GlobalSign/R3/Timestamping-G2-SHA256", "https://jp.globalsign.com/repository/common/cer/sha2TimestampingCA_v2.cer")
		// ネット選挙対応ウェブサイト用証明書 is the same as 企業認証SSL
		// ネット選挙対応ウェブサイト用EV証明書 is the same as EV SSL
		// ネット選挙対応電子メール用証明書
			download("GlobalSign/R1/PersonalSign-G2-SHA1-2",   "https://jp.globalsign.com/repository/common/cer/pscacert_v2.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign/R3/PersonalSign-G2-SHA256-2", "https://jp.globalsign.com/repository/common/cer/pscacert_v3.cer", shouldBeSameAsExistingDst = true)
	// 【R3用】中間CA証明書 (SHA256:2016年10月14日以降有効)
		download("GlobalSign/R3/DomainSSL-G2-SHA256", "https://jp.globalsign.com/repository/common/cer/gsdomainvalsha2g2r3.cer")
		download("GlobalSign/R3/OrganizationSSL-G2-SHA256", "https://jp.globalsign.com/repository/common/cer/gsorganizationvalsha2g2r3.cer")
		download("GlobalSign/R3/CloudSSL-G3", "https://jp.globalsign.com/repository/common/cer/cloudsslsha2g3r3.cer", shouldBeSameAsExistingDst = true)
	// 新・中間CA証明書 (EV SSL SHA256:2016年10月31日以降有効)
		download("GlobalSign/R3/ExtendedSSL-G3", "https://jp.globalsign.com/repository/common/cer/gsextendvalsha2g3r3.cer", shouldBeSameAsExistingDst = true)
	// 新・中間CA証明書 (SHA-1:2016年4月4日以降有効、SHA256:2016年7月11日以降有効)
		// コードサイニング証明書
			download("GlobalSign/R1/CodeSigningStandard-G3", "https://jp.globalsign.com/repository/common/cer/gscodesigng3ocsp_v2.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign/R3/CodeSigningStandard-G3", "https://jp.globalsign.com/repository/common/cer/gscodesignsha2g3ocsp.cer", shouldBeSameAsExistingDst = true)
		// EVコードサイニング証明書
			download("GlobalSign/R3/CodeSigningEV-G3", "https://jp.globalsign.com/repository/common/cer/gsextendcodesignsha2g3ocsp.cer", shouldBeSameAsExistingDst = true)
		// 電子証明書（S/MIME）用証明書, ネット選挙対応電子メール用証明書, クライアント証明書・マネージドPKI Lite
			download("GlobalSign/R1/PersonalSign-G3-SHA1-2", "https://jp.globalsign.com/repository/common/cer/gspersonalsign2g3ocsp_v2.cer", shouldBeSameAsExistingDst = true) 
			download("GlobalSign/R3/PersonalSign-G3-SHA256-2", "https://jp.globalsign.com/repository/common/cer/gspersonalsign2sha2g3ocsp.cer", shouldBeSameAsExistingDst = true)
	// テスト証明書に必要なルート/中間CA証明書
		// SSLサーバ証明書
			// ルート証明書
				// SHA-1・SHA256共通 is the same as GlobalSign/R1
			// 中間CA 証明書
				// SHA-1 is the same as GlobalSign/R1/DomainSSL-G2-SHA1
				// SHA-256 is the same as GlobalSign/R1/DomainSSL-G2
		// 電子署名(S/MIME)用証明書
			download("GlobalSign/R1/PersonalSign-G3-SHA1-1",   "https://jp.globalsign.com/repository/common/cer/smimetestcacertsha1g3.cer", shouldBeSameAsExistingDst = true)
			download("GlobalSign/R3/PersonalSign-G2-SHA256-1", "https://jp.globalsign.com/repository/common/cer/smimetestcacertsha2.cer", shouldBeSameAsExistingDst = true)
		// マネージドPKI Lite
			download("GlobalSign-Staging/R1",          "https://jp.globalsign.com/repository/common/cer/ca-SHA1-G3_root.cer")
			download("GlobalSign-Staging/R3-SHA256",   "https://jp.globalsign.com/repository/common/cer/ca-SHA2-G2_root.cer")
			download("GlobalSign-Staging/R1/PersonalSign-G3-SHA1-2", "https://jp.globalsign.com/repository/common/cer/ca_PS2-SHA1-G3_V2.cer")
			download("GlobalSign-Staging/R3-SHA256/PersonalSign-G3-SHA256-2",   "https://jp.globalsign.com/repository/common/cer/ca_PS2-SHA2-G3.cer")
		// PDF文書署名用証明書
			// その1 is the same as Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256
			// その2 is the same as Adobe/Adobe Root CA/GlobalSign-CDS-PrimarySHA256/GlobalSign-CDS-SHA256

// MIND DIACERT
// https://www.diacert.jp/repository/repository02.html
download("MIND-DIACERT/G2", "https://www.diacert.jp/repository/DIACERTCA-G2.cer")
download("MIND-DIACERT/G1", "https://www.diacert.jp/repository/DIACERTCA.cer")
download("MIND-DIACERT/G2withG1", "https://www.diacert.jp/repository/DIACERTCA-LINK_G2withG1.cer")
download("MIND-DIACERT/G1withG2", "https://www.diacert.jp/repository/DIACERTCA-LINK_G1withG2.cer")

// MIND DIACERT-PLUS
// https://www.diacert.jp/plus/repository/repository02.html
download("MIND-DIACERT-PLUS/G1", "https://www.diacert.jp/plus/repository/DIACERTPLUSCA.cer")

// MIND JapanNet Secure Network
// https://www.japannet.jp/securenw/repository/index.html
download("MIND-SecureNetwork/G1", "https://www.japannet.jp/jsnca/repository/sntroot.cer")
download("MIND-SecureNetwork/G2", "https://www.japannet.jp/jsnca/repository/sntrootg2.cer")

// MIND Enterprise Premium
// https://www.eppcert.jp/repository/index.html
download("MIND-EnterprisePremium/G1", "https://www.japannet.jp/epca/repository/epca.cer")
download("MIND-EnterprisePremium/G2", "https://www.eppcert.jp/repository/epg2ca.cer")
download("MIND-EnterprisePremium/G3", "https://www.eppcert.jp/repository/epg3ca.cer")

// SECOM
// https://repository.secomtrust.net/

// SECOM Passport
// https://repository.secomtrust.net/PassportFor/G-ID/index.html
download("SECOM-Passport/G3", "https://repository.secomtrust.net/PassportFor/G-ID/repository/g-idca03.crt")
download("SECOM-Passport/G2", "https://repository.secomtrust.net/PassportFor/G-ID/repository/g-idca02.crt")
download("SECOM-Passport/G3withG2", "https://repository.secomtrust.net/PassportFor/G-ID/repository/g-idca03-NewWithOld.crt")
download("SECOM-Passport/G2withG3", "https://repository.secomtrust.net/PassportFor/G-ID/repository/g-idca03-OldWithNew.crt")

// SECOM Trust.net
// https://repository.secomtrust.net/rootrepository/index.html
//download("SECOM-Trust/ValiCert", "https://repository.secomtrust.net/rootrepository/rootca.cer") // 404 as of 2019-02-01

// SECOM Security Communication
// https://repository.secomtrust.net/SC-Root1/index.html
download("SECOM-SecurityCommunication/R1", "https://repository.secomtrust.net/SC-Root1/SCRoot1ca.cer")
//download("SECOM-SecurityCommunication/R1withValiCert", "https://repository.secomtrust.net/rootrepository/STroot2SCroot.cer") // 404 as of 2019-02-01
//download("SECOM-SecurityCommunication/R1withValiCert-2712", "https://repository.secomtrust.net/rootrepository/old2712_STroot2SCroot.cer") // 404 as of 2019-02-01
//download("SECOM-SecurityCommunication/R1withValiCert-2711", "https://repository.secomtrust.net/rootrepository/old2711_STroot2SCroot.cer") // 404 as of 2019-02-01
// https://repository.secomtrust.net/SC-Root2/index.html
download("SECOM-SecurityCommunication/R2", "https://repository.secomtrust.net/SC-Root2/SCRoot2ca.cer")
// https://repository.secomtrust.net/SC-Root3/index.html
download("SECOM-SecurityCommunication/R3", "https://repository.secomtrust.net/SC-Root3/SCRoot3ca.cer")
// https://repository.secomtrust.net/SC-ECC-Root1/index.html
download("SECOM-SecurityCommunication/ECC-R1", "https://repository.secomtrust.net/SC-ECC-Root1/SCECCRoot1ca.cer")
// https://repository.secomtrust.net/EV-Root1/index.html
//download("SECOM-SecurityCommunication/EV-R1", "https://repository.secomtrust.net/EV-Root1/EVRoot1ca.cer") // 404 as of 2019-02-01

// JIPDEC JCAN
// https://www.jipdec.or.jp/repository/
download("GlobalSign/R3/JCAN-R1", "https://itc.jipdec.or.jp/common/images/jcan_root_ca1.cer")
