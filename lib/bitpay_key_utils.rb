# license Copyright 2011-2014 BitPay, Inc., MIT License
# see http://opensource.org/licenses/MIT
# or https://github.com/bitpay/php-bitpay-client/blob/master/LICENSE

libdir = File.dirname(__FILE__)
$LOAD_PATH.unshift(libdir) unless $LOAD_PATH.include?(libdir)
require 'bitpay/key_utils'
require 'bitpay/key_version'

# BitPay module is a top level module that includes the key_utils and client classes.
# This gem implements the key_utilities methods.
module BitPay
  MISSING_PEM = 'No pem file specified. Pass pem string'
  class BitPayError < StandardError; end
  class ArgumentError < ArgumentError; end
  class ConnectionError < Errno::ECONNREFUSED; end
end
