require 'openssl'

def s2b str
  [str].pack("H*")
end

CA_EXP = 0x03
CA_MOD = "AB79FCC952089696"+
    "7E776E64444E5DCD"+
    "D6E13611874F3985"+
    "722520425295EEA4"+
    "BD0C2781DE7F31CD"+
    "3D041F565F747306"+
    "EED62954B17EDABA"+
    "3A6C5B85A1DE1BEB"+
    "9A34141AF38FCF82"+
    "79C9DEA0D5A6710D"+
    "08DB4124F0419455"+
    "87E20359BAB47B75"+
    "75AD94262D4B25F2"+
    "64AF33DEDCF28E09"+
    "615E937DE32EDC03"+
    "C54445FE7E382777"

ISSUER_CERT =  s2b("6fc463ddd02a73b35c84daa726ee4d3f"+
"25326622f1d82a074811ae2b1b9a67cb"+
"58d955735ee635d571f39b5ce0f64d71"+
"af732d83f37e2bd56d67221376c99b14"+
"3b0530f2fceab2fe6350c62fcea0c163"+
"e4bd84ecb84342d05ebfb68f6a9e4996"+
"d2cab963962e548a5beef5efffd01955"+
"b92ab5064bacb0c8bc3e1c40286dfefc")

ISSUER_EXP=0x03
ISSUER_MOD="bdbadb8ec4f489c0d60e14632cceaa41c8dfd12ecf3651db4c847dba8c755d6e2f462cfd99e17561ee6e6ac60f31585790c6f95f065e7d2a2c7319070bfcb9448b5127b6c90963de7f6211fd34ebaa004750628147a8d4db9aa90da8"+"d80d54fbecb3e76b0b571a701dff35d361d9f9b3"

SDA_CERT = s2b( 
"ae4cf9d49cd3863167b9a24790372fe1"+
"f2d71dc8c068ed19364907ce09e166bb"+
"0777bed00db7d2c2e4000079da50279e"+
"1f6bcf1d703d2490c06357b1f75122ed"+
"cb9e9657e4df9ecc00f8dfc65da791ac"+
"ad207f115095676e980c4a08bec8a557"+
"3438d05274e23a1c3b0b8e0562725ea0"
)

def decode_issuer_cert
  # find cert
  cert = nil
  @card_data.each {|tlv|
    if tlv.tag == "\x90"
      cert = tlv.value
    end 
  }
  decoded = rsa_public cert, CA_MOD, CA_EXP
  hexy(decoded)
end

def decode_sda_cert
  sda = nil
  @card_data.each {|tlv|
    if tlv.tag == "\x93"
      sda = tlv.value
    end
  }
  decoded = rsa_public cert, ISSUER_MOD, ISSUER_EXP
  hexy(decoded)
end

# create a sha1 digest of a String containing raw byte data.
def sha1 data
  OpenSSL::Digest.digest "sha1", data
end

def rsa_public data, n, e
  pk = OpenSSL::PKey::RSA.new
  pk.n = OpenSSL::BN.new(n, 16)
  pk.e = e

  pad = OpenSSL::PKey::RSA::NO_PADDING
  pk.public_decrypt(data, pad)
end

