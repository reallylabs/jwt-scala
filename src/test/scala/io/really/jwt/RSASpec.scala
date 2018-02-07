/**
 * Copyright (C) 2014-2015 Really Inc. <http://really.io>
 */
package io.really.jwt

import io.really.jwt.JWTException.{InvalidPrivateKey, InvalidPublicKey}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMWriter
import org.scalatest.{FlatSpec, Matchers}
import play.api.libs.json.Json
import java.io._
import java.security._


class RSASpec extends FlatSpec with Matchers {

  object MyKeyStore {
    if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    val kp = KeyPairGenerator.getInstance("RSA").generateKeyPair()
    val kp2 = KeyPairGenerator.getInstance("RSA").generateKeyPair()
    val privateKey: PrivateKey = kp.getPrivate
    val publicKey: PublicKey = kp.getPublic

    val otherPublicKey: PublicKey = kp2.getPublic

    def privateKeyStr = printKey(privateKey)
    def publicKeyStr = printKey(publicKey)

    def otherPublicKeyStr = printKey(otherPublicKey)

    def printKey(key:Object): String ={
      val writer = new StringWriter
      val pemWriter = new PEMWriter(writer)
        pemWriter.writeObject(key)
        pemWriter.flush()
        pemWriter.close()
      PemUtil.removeBeginEnd(writer.toString)
    }
  }

  "encode" should "generate json web token" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode(MyKeyStore.privateKeyStr, payload, Json.obj(), Some(Algorithm.RS256) )
    assertResult(JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT].payload)(payload)
  }

  it should "generate json web token with no provided secret" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeWithoutSecret(payload, Json.obj(), Some(Algorithm.RS256))
    assertResult(JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT].payload)(payload)
  }

  "verify" should "prove a payload encoded with privateKey can be verified with publicKey" in{
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com").toString()
    val signature = JWT.signRsa(Algorithm.RS256, payload, MyKeyStore.privateKeyStr)
    assert(JWT.verifyRsa(Algorithm.RS256, MyKeyStore.publicKeyStr, payload, signature))
  }

  "decode" should "decode token and verify it" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode(MyKeyStore.privateKeyStr, payload, Json.obj(), Some(Algorithm.RS256))
    val token = JWT.decode(jwt, Some(MyKeyStore.publicKeyStr)).asInstanceOf[JWTResult.JWT]
    assertResult(payload)(token.payload)
    assertResult(Json.obj("alg" -> Algorithm.RS256, "typ" -> "JWT"))(token.header.toJson)
  }

  it should "return Invalid Signature if you try decode with a valid incorrect token" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode(MyKeyStore.privateKeyStr, payload, Json.obj(), Some(Algorithm.RS256))
    assertResult(JWTResult.InvalidSignature)(JWT.decode(jwt, Some(MyKeyStore.otherPublicKeyStr)))
  }

  it should "return throw an InvalidPrivateKey if you try encode with an invalid PrivateKey" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    an [InvalidPrivateKey] should be thrownBy(JWT.encode("invalid", payload, Json.obj(), Some(Algorithm.RS256)))
  }

  it should "return throw an InvalidPublicKey if you try encode with an invalid PublicKey" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode(MyKeyStore.privateKeyStr, payload, Json.obj(), Some(Algorithm.RS256))
    an [InvalidPublicKey] should be thrownBy(JWT.decode(jwt, Some("invalid")))
  }

  it should "decode a token encoded with no secret" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeWithoutSecret(payload, Json.obj(), Some(Algorithm.RS256))
    val token = JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT]

    assertResult(payload)(token.payload)
    assertResult(Json.obj("alg" -> Algorithm.RS256, "typ" -> "JWT"))(token.header.toJson)
  }

  it should "return Invalid Signature if you try decode RSXXX signed JWT with crafted HSXXX algorithm header" in {
    val payload = Json.obj("name" -> "Test", "email" -> "test@exemple.com")
    val publicKeyStr = MyKeyStore.publicKeyStr
    val privateKeyStr = MyKeyStore.privateKeyStr
    val jwt_valid = JWT.encode(privateKeyStr, payload, Json.obj(), Some(Algorithm.RS256))
    val jwt_invalid = JWT.encode(publicKeyStr, payload, Json.obj(), Some(Algorithm.HS256))

    assertResult(payload)(JWT.decode(jwt_valid, Some(publicKeyStr)).asInstanceOf[JWTResult.JWT].payload)
    assertResult(JWTResult.InvalidSignature)(JWT.decode(jwt_invalid, Some(publicKeyStr)))
  }

}
