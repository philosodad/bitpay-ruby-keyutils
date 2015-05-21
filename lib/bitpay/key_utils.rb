# license Copyright 2011-2014 BitPay, Inc., MIT License
# see http://opensource.org/licenses/MIT
# or https://github.com/bitpay/php-bitpay-client/blob/master/LICENSE

require 'openssl'
require 'ecdsa'
require 'securerandom'
require 'digest/sha2'
require 'pry'
module BitPay
  # KeyUtils contains public class methods for:
  # - Generating a new key
  # - Creating the BitPay SIN for the key
  # - Retrieving the compressed public key
  # - Signing the sha256 hash of a message
  class KeyUtils
    class << self
      def generate_pem
        key = OpenSSL::PKey::EC.new('secp256k1')
        key.generate_key
        key.to_pem
      end

      def create_key pem
        OpenSSL::PKey::EC.new(pem)
      end

      def create_new_key
        key = OpenSSL::PKey::EC.new('secp256k1')
        key.generate_key
        key
      end

      def get_private_key key
        key.private_key.to_int.to_s(16)
      end

      def get_public_key key
        key.public_key.group.point_conversion_form = :compressed
        key.public_key.to_bn.to_s(16).downcase
      end

      def get_private_key_from_pem pem
        fail BitPayError, MISSING_PEM unless pem
        key = OpenSSL::PKey::EC.new(pem)
        get_private_key key
      end

      def get_public_key_from_pem pem
        fail BitPayError, MISSING_PEM unless pem
        key = OpenSSL::PKey::EC.new(pem)
        get_public_key key
      end

      # http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html
      # https://en.bitcoin.it/wiki/Identity_protocol_v1

      def generate_sin_from_pem pem
        key = get_public_key_from_pem pem
        public_key = bytes_from_hex key
        step_one = Digest::SHA256.hexdigest(public_key)
        step_two = Digest::RMD160.hexdigest(bytes_from_hex(step_one))
        step_three = "0F02#{step_two}"
        step_four_a = Digest::SHA256.hexdigest(bytes_from_hex(step_three))
        step_four = Digest::SHA256.hexdigest(bytes_from_hex(step_four_a))
        step_five = step_four[0..7]
        step_six = "#{step_three}#{step_five}"
        encode_base58(step_six)
      end

      ## Generate ECDSA signature
      #  This is the last method that requires the ecdsa gem, which we would like to replace

      def sign message, privkey
        group = ECDSA::Group::Secp256k1
        digest = Digest::SHA256.digest(message)
        signature = nil
        while signature.nil?
          temp_key = 1 + SecureRandom.random_number(group.order - 1)
          signature = ECDSA.sign(group, privkey.to_i(16), digest, temp_key)
          return ECDSA::Format::SignatureDerString.encode(signature).unpack('H*').first
        end
      end

      def sign_with_pem pem, message
        priv = get_private_key_from_pem pem
        sign(message, priv)
      end

      ########## Private Class Methods ################

      ## Base58 Encoding Method
      #

      private

      def bytes_from_hex hex
        hex.to_i(16).to_bn.to_s(2)
      end

      def encode_base58 data
        code_string = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base = 58
        x = data.hex
        output_string = ''

        while x > 0
          remainder = x % base
          x /= base
          output_string << code_string[remainder]
        end

        pos = 0
        while data[pos, 2] == '00'
          output_string << code_string[0]
          pos += 2
        end

        output_string.reverse
      end
    end
  end
end
