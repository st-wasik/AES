module Main where

import Codec.Crypto.AES
import Control.Applicative
import Data.Bits as B
import Data.ByteString as BS
import Data.ByteString.Internal
import Data.Char
import Data.List as L
import System.Environment

main :: IO ()
main = do
    args <- getArgs
    dispatch args

dispatch ("encodeECB":fileIn:fileOut:_) = do
    fc <- BS.readFile fileIn
    BS.writeFile fileOut . BS.concat . codeBlocks Encrypt $ createBlockList fc

dispatch ("decodeECB":fileIn:fileOut:_) = do
    fc <- BS.readFile fileIn
    BS.writeFile fileOut . BS.concat . codeBlocks Decrypt $ createBlockList fc

dispatch ("CTR":fileIn:fileOut:_) = do
    fc <- BS.readFile fileIn
    BS.writeFile fileOut . BS.concat $ codeCTR (createBlockList fc) 0

dispatch ("encodeCBC":fileIn:fileOut:_) = do
    fc <- BS.readFile fileIn
    BS.writeFile fileOut . BS.concat . codeBlocksCBC Encrypt $ createBlockList fc

dispatch ("decodeCBC":fileIn:fileOut:_) = do
    fc <- BS.readFile fileIn
    BS.writeFile fileOut . BS.concat . codeBlocksCBC Decrypt $ createBlockList fc
    

dispatch _ = Prelude.putStrLn "Wrong argument - nothing to do."
                  
key = BS.pack $ fmap c2w "0123456789ABCDEF"
iv =  BS.pack $ fmap c2w "ABCDEF0123456789"
nonce ="c56e12f4"

createBlockList :: BS.ByteString -> [BS.ByteString]
createBlockList t
    | BS.null t = []
    | len < 16 = [BS.take 16 text16]
    | len >= 16 = BS.take 16 t : createBlockList (BS.drop 16 t)
    where text16 = BS.append t . BS.pack $ c2w <$> L.replicate 16 ' '
          len = BS.length t 

codeBlocks :: Direction -> [BS.ByteString] -> [BS.ByteString]
codeBlocks d (b:bs) = codeECB d b : codeBlocks d bs
codeBlocks _ [] = []

codeBlocksCBC :: Direction -> [BS.ByteString] -> [BS.ByteString]
codeBlocksCBC d (b:bs) = codeCBC d b : codeBlocks d bs
codeBlocksCBC _ [] = []

codeCTR :: [BS.ByteString] -> Int -> [BS.ByteString]
codeCTR (b:bs) counter = codedText : codeCTR bs (counter + 1)
    where p = BS.pack $ fmap c2w (nonce ++ pad8 counter)
          codedNonce = codeECB Encrypt p
          codedText = Main.xor codedNonce b
codeCTR [] _ = []

codeECB :: Direction -> BS.ByteString -> BS.ByteString
codeECB = crypt' ECB key iv

codeCBC :: Direction -> BS.ByteString -> BS.ByteString
codeCBC = crypt' CBC key iv

-- "00000001" from "1"
pad8 :: Int -> String
pad8 e = L.replicate (8 - if eLen <= 8 then eLen else 8) '0' ++ (L.reverse . L.take 8 $ L.reverse showE)
    where eLen = L.length showE
          showE = show e

xor :: BS.ByteString -> BS.ByteString -> BS.ByteString
xor t1 t2 = BS.pack $ BS.zipWith B.xor t1 t2

-- Code not splitted String
code :: Direction -> BS.ByteString -> BS.ByteString
code d t
    | BS.null t = BS.empty
    | len < 16 = codeECB d $ BS.take 16 text 
    | len >= 16 = BS.append (codeECB d $ BS.take 16 t) (code d $ BS.drop 16 t)
    where text = BS.append t . BS.pack $ c2w <$> L.replicate 16 ' '
          len = BS.length t 