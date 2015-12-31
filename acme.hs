{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

--------------------------------------------------------------------------------
-- | Get a certificate from Let's Encrypt using the ACME protocol.

module Main where

import Control.Concurrent (threadDelay)
import Control.Monad (mzero)
import Crypto.Number.Serialize (i2osp)
import Data.ByteString.Builder (byteString)
import Data.Aeson (encode, object, FromJSON(..), ToJSON(..), Value(Object), (.=), (.:), (.:?))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Base64.URL as Base64
import Data.Digest.Pure.SHA (bytestringDigest, sha256)
import Data.Text.Encoding (decodeUtf8)
import Network.Http.Client
  ( baselineContextSSL, buildRequest, concatHandler, get, getHeader, http
  , jsonHandler, openConnectionSSL, receiveResponse, sendRequest
  , setContentLength, setContentType, Method(POST))
import OpenSSL.EVP.PKey
import OpenSSL.PEM (readPublicKey)
import OpenSSL.RSA
import System.Environment (getArgs)
import System.IO.Streams (connect)
import qualified System.IO.Streams as Streams
import System.IO.Streams.Builder (builderStream)
import System.IO.Streams.File (withFileAsInput)
import System.Process (readProcess)


--------------------------------------------------------------------------------
email :: String
email = "noteed@gmail.com"

terms :: String
terms = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

server :: ByteString
-- server = "acme-staging.api.letsencrypt.org"
server = "acme-v01.api.letsencrypt.org"

--------------------------------------------------------------------------------
main :: IO ()
main = do
  [domain] <- getArgs
  userKey_ <- readFile "user.pub" >>= readPublicKey
  case toPublicKey userKey_ of
    Nothing -> error "Not a public RSA key."
    Just (userKey :: RSAPubKey) -> do

      -- Create user account
      putStrLn "Creating user account..."
      signPayload (domain ++ "/registration") userKey (registration email)
      (_ :: Value) <- postBody domain "registration" "/acme/new-reg"

      -- Obtain a challenge
      putStrLn "Obtaining challenge values..."
      signPayload (domain ++ "/challenge-request") userKey (authz domain)
      cr <- postBody domain "challenge-request" "/acme/new-authz"

      -- Answser the challenge
      let thumb = thumbprint (JWK (rsaE userKey) "RSA" (rsaN userKey))
          http01_ = http01 cr
          token = (BC.pack . rToken) http01_
          thumbtoken = LB.fromChunks [token, ".", thumb]

      LB.writeFile (domain ++ "/content.txt") thumbtoken
      putStrLn ("Exposing challenge values using " ++ domain ++ "/serve.sh...")
      serveThumbprint domain token

      -- Notify Let's Encrypt we answsered the challenge
      signPayload (domain ++ "/challenge-response") userKey
        (challenge thumbtoken)
      (_ :: Value) <- postBody domain "challenge-response"
        (BC.pack (rUri http01_))

      -- Wait for challenge validation
      putStrLn "Waiting for validation..."
      let loop = do
            threadDelay (1 * 1000 * 1000)
            x <- get (BC.pack (rUri http01_)) jsonHandler
            if rStatus x == "valid" then return () else loop
      loop

      -- Send a CSR and get a certificate
      putStrLn "Requesting certificate..."
      csr_ <- B.readFile (domain ++ "/domain.der")
      signPayload (domain ++ "/csr-request") userKey (csr csr_)
      content <- postBody' domain "csr-request" "/acme/new-cert"
      B.writeFile (domain ++ "/domain.cert.der") content
      putStrLn ("Certificate written to " ++ domain ++ "/domain.cert.der")


--------------------------------------------------------------------------------
-- | Sign and write a payload to a file with a nonce-protected header.
signPayload name key payload = do
  nonce_ <- nonce
  let protected = b64 (header key nonce_)
  writePayload name protected payload
  sig <- sign name
  writeBody name key protected payload sig

-- | Write a payload to file with a nonce-protected header.
writePayload name protected payload =
  LB.writeFile (name ++ ".txt") (LB.fromChunks [protected, ".", payload])

-- | Sign a payload file using the user key.
sign name = do
  sign_ (name ++ ".txt") (name ++ ".sig")
  sig_ <- B.readFile (name ++ ".sig")
  return (b64 sig_)

sign_ inp out = do
  _ <- readProcess "openssl"
    [ "dgst", "-sha256"
    , "-sign", "user.key"
    , "-out", out
    , inp
    ]
    ""
  return ()

-- | Write a signed payload to a file. It can be used as the body of a POST
-- request.
writeBody name key protected payload sig = LB.writeFile (name ++ ".body")
  (encode (Request (header' key) protected payload sig))

serveThumbprint domain token = do
  _ <- readProcess (domain ++ "/serve.sh")
    [ domain ++ "/content.txt"
    , BC.unpack token
    ]
    ""
  return ()

postBody domain name url = do
  c <- postBody_ domain name url
  x <- receiveResponse c jsonHandler
  print x
  return x

postBody' domain name url = do
  c <- postBody_ domain name url
  x <- receiveResponse c concatHandler
  print x
  return x

postBody_ domain name url = do
  content <- B.readFile (domain ++ "/" ++ name ++ ".body")
  ctx <- baselineContextSSL
  c <- openConnectionSSL ctx server 443
  q <- buildRequest $ do
    http POST url
    setContentType "application/json"
    setContentLength (fromIntegral (B.length content))
  sendRequest c q
    (\o -> Streams.write (Just (byteString content)) o
    >> Streams.write Nothing o)
  return c

--------------------------------------------------------------------------------
-- | Base64URL encoding of Integer with padding '=' removed.
b64i = b64 . i2osp

b64 = B.takeWhile (/= 61) . Base64.encode

toStrict = B.concat . LB.toChunks

header' key = Header "RS256" (JWK (rsaE key) "RSA" (rsaN key)) Nothing

header key nonce = (toStrict . encode)
  (Header "RS256" (JWK (rsaE key) "RSA" (rsaN key)) (Just nonce))

-- | Registration payload to sign with user key.
registration email = (b64 . toStrict . encode) (Reg email terms)

-- | Challenge request payload to sign with user key.
authz = b64. toStrict . encode . Authz

-- | Challenge response payload to sign with user key.
challenge = b64 . toStrict . encode . Challenge . toStrict

-- | CSR request payload to sign with user key.
csr = b64 . toStrict . encode . CSR . b64

thumbprint = b64 . toStrict .bytestringDigest . sha256 . encodeOrdered

-- | There is an `encodePretty'` in `aeson-pretty`, but do it by hand here.
encodeOrdered JWK{..} = LC.pack $
  "{\"e\":\"" ++ hE' ++ "\",\"kty\":\"" ++ hKty ++ "\",\"n\":\"" ++ hN' ++ "\"}"
  where
  hE' = BC.unpack (b64i hE)
  hN' = BC.unpack (b64i hN)


--------------------------------------------------------------------------------
nonce = do
  mnonce <- get (BC.concat ["https://", server, "/directory"])
    (\r _ -> return (getHeader r "Replay-Nonce"))
  case mnonce of
    Nothing -> error "Can't get Nonce."
    Just x -> return x

--------------------------------------------------------------------------------
data Header = Header
  { hAlg :: String
  , hJwk :: JWK
  , hNonce :: Maybe ByteString
  }
  deriving Show

data JWK = JWK
  { hE :: Integer
  , hKty :: String
  , hN :: Integer
  }
  deriving Show

instance ToJSON Header where
  toJSON Header{..} = object $
    [ "alg" .= hAlg
    , "jwk" .= toJSON hJwk
    ] ++ maybe [] ((:[]) . ("nonce" .=) . decodeUtf8) hNonce

instance ToJSON JWK where
  toJSON JWK{..} = object
    [ "e" .= decodeUtf8 (b64i hE)
    , "kty" .= hKty
    , "n" .= decodeUtf8 (b64i hN)
    ]

data Reg = Reg
  { rMail :: String
  , rAgreement :: String
  }
  deriving Show

instance ToJSON Reg where
  toJSON Reg{..} = object
    [ "resource" .= ("new-reg" :: String)
    , "contact" .= ["mailto:" ++ rMail]
    , "agreement" .= rAgreement
    ]

data Request = Request
  { rHeader :: Header
  , rProtected :: ByteString
  , rPayload :: ByteString
  , rSignature :: ByteString
  }
  deriving Show

instance ToJSON Request where
  toJSON Request{..} = object
    [ "header" .= toJSON rHeader
    , "protected" .= decodeUtf8 rProtected
    , "payload" .= decodeUtf8 rPayload
    , "signature" .= decodeUtf8 rSignature
    ]

data Authz = Authz
  { aDomain :: String
  }

instance ToJSON Authz where
  toJSON Authz{..} = object
    [ "resource" .= ("new-authz" :: String)
    , "identifier" .= object
      [ "type" .= ("dns" :: String)
      , "value" .= aDomain
      ]
    ]

data Challenge = Challenge
  { cKeyAuth :: ByteString
  }

instance ToJSON Challenge where
  toJSON Challenge{..} = object
    [ "resource" .= ("challenge" :: String)
    , "keyAuthorization" .= decodeUtf8 cKeyAuth
    ]

data CSR = CSR ByteString
  deriving Show

instance ToJSON CSR where
  toJSON (CSR s) = object
    [ "resource" .= ("new-cert" :: String)
    , "csr" .= decodeUtf8 s
    ]

--------------------------------------------------------------------------------
data ChallengeResponse = ChallengeResponse
  { rStatus :: String
  , rChallenges :: [RegChallenge]
  }
  deriving Show

instance FromJSON ChallengeResponse where
  parseJSON (Object v) = do
    status <- v .: "status"
    challenges <- v .:? "challenges"
    return ChallengeResponse
      { rStatus = status
      , rChallenges = maybe [] id challenges
      }
  parseJSON _ = mzero

data RegChallenge = RegChallenge
  { rToken :: String
  , rUri :: String
  , rType :: String
  }
  deriving Show

instance FromJSON RegChallenge where
  parseJSON (Object v) = do
    token <- v .: "token"
    uri <- v .: "uri"
    typ <- v .: "type"
    return RegChallenge
      { rToken = token
      , rUri = uri
      , rType = typ
      }
  parseJSON _ = mzero

http01 ChallengeResponse{..} = case filter f rChallenges of
  [x] -> x
  _ -> error "No http-01 chanllenge."
  where f RegChallenge{..} = rType == "http-01"
