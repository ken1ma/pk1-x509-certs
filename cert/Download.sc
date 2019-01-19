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
