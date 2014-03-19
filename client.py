from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64encode
import requests
import simplejson


class Client(object):

    def __init__(self, protocol='http', server='api.redshelf.com', port=80):
        self.protocol = protocol
        self.server = server
        self.port = port
        self.version = 'v1'

        self.crypt = RSACrypto()

        self.username = ''

    ## default endpoints
    ## ------------

    def index(self):
        """
        API Index
        GET /
        """
        r = requests.get(self._get_server())
        try:
            return r.json()
        except Exception:
            return self._error(r)

    def repeat(self, data):
        """
        Repeater (debug & testing)
        POST /repeat/
        """

        test_data = {'request': simplejson.dumps(data)}
        r = requests.post(self._get_endpoint('repeat'), test_data, headers=self._get_signed_headers(data))
        try:
            return r.json()
        except Exception:
            return self._error(r)

    def profile(self):
        """
        Profile information
        POST /profile/
        """
        r = requests.get(url=self._get_endpoint('profile'), headers=self._get_signed_headers())
        try:
            return r.json()
        except Exception:
            return self._error(r)

    ## helpers
    ## ------------

    def _error(self, r):
        return {'code': r.status_code, 'text': r.text}

    def _get_server(self):
        if self.port:
            return str(self.protocol) + '://' + str(self.server) + ':' + str(self.port) + '/'
        else:
            return str(self.protocol) + '://' + str(self.server) + '/'

    def _get_endpoint(self, ep, id=None, action=None):
        if id:
            if action:
                return self._get_server() + str(ep) + '/' + str(id) + '/' + str(action) + '/'
            else:
                return self._get_server() + str(ep) + '/' + str(id) + '/'
        else:
            return self._get_server() + str(ep) + '/'

    def _get_version_endpoint(self, ep, id=None, action=None):
        if id:
            if action:
                return self._get_server() + str(self.version) + '/' + str(ep) + '/' + str(id) + '/' + str(action) + '/'
            else:
                return self._get_server() + str(self.version) + '/' + str(ep) + '/' + str(id) + '/'
        else:
            return self._get_server() + str(self.version) + '/' + str(ep) + '/'

    def _get_signed_headers(self, data=None):
        if not data:
            sig = self.crypt.sign_data(self.username)
        else:
            sig = self.crypt.sign_data(simplejson.dumps(data))

        headers = {'signature': sig, 'api_user': self.username, 'user': self.username, 'version': self.version, 'auth_method': 'CRYPTO'}
        return headers

    def _get_request_data(self, data):
        return {'request': simplejson.dumps(data)}

    def set_user(self, name):
        self.username = name

    def set_key(self, val):
        self.crypt.set_private_key(val)

    def load_key(self, filename):
        self.crypt.load_private_key(filename)


class RSACrypto(object):

    def __init__(self):
        self.__public_key = None
        self.__private_key = None

    def encrypt_RSA(self, message):
        rsakey = RSA.importKey(self.__public_key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message)
        return encrypted.encode('base64')

    def sign_data(self, data):
        rsakey = RSA.importKey(self.__private_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        digest.update(data)
        sign = signer.sign(digest)
        return b64encode(sign)

    def set_public_key(self, var):
        self.__public_key = var

    def load_public_key(self, file):
        self.__public_key = open(file, "r").read()

    def set_private_key(self, var):
        self.__private_key = var

    def load_private_key(self, file):
        self.__private_key = open(file, "r").read()


class ClientV1(Client):

    def __init__(self, protocol='http', server='api.redshelf.com', port=80):
        super(ClientV1, self).__init__(protocol, server, port)
        self.version = 'v1'

    ## Book endpoints
    ## ------------

    def book(self, hash_id=None, isbn=None):
        """
        Book endpoint
        GET /v1/book/<hash_id>/
        GET /v1/book/isbn/<isbn/

        args: hash_id (str) OR isbn (str)
        """
        if hash_id:
            r = requests.get(url=self._get_version_endpoint('book', hash_id), headers=self._get_signed_headers())
        elif isbn:
            r = requests.get(url=self._get_version_endpoint('book', 'isbn', isbn), headers=self._get_signed_headers())
        else:
            raise ClientException("Please provide the book hash_id or ISBN field.")

        try:
            return r.json()
        except Exception:
            return self._error(r)

    def book_search(self, isbn=None, title=None):
        """
        Book search endpoint
        POST /v1/book/search/

        args: isbn (list <str>), title (str)
        """
        payload = {'isbn': isbn, 'title': title}
        request_data = self._get_request_data(payload)
        r = requests.post(url=self._get_version_endpoint('book', 'search'), data=request_data, headers=self._get_signed_headers(payload))

        try:
            return r.json()
        except Exception:
            return self._error(r)

    ## User endpoints
    ## ------------

    def invite_user(self, email=None, first_name=None, last_name=None, label=None):
        """
        User invite endpoint
        POST /v1/user/invite/

        args: email (str), first_name (str), last_name (str), label (str) <optional>

        notes: Create a new RedShelf user and send them an invite email with a generated password.  Requires the
               'invite_user' scope and management permission for the associated white label (if provided).
        """
        payload = {'email': email, 'first_name': first_name, 'last_name': last_name, 'label': label}
        request_data = self._get_request_data(payload)
        r = requests.post(url=self._get_version_endpoint('user', 'invite'), data=request_data, headers=self._get_signed_headers(payload))

        try:
            return r.json()
        except Exception:
            return self._error(r)

    def user(self, username=None, email=None):
        """
        User endpoint
        GET /v1/user/

        args: username (str), email (str)
        """

        if username:
            r = requests.get(url=self._get_version_endpoint('user', username), headers=self._get_signed_headers())
        elif email:
            r = requests.get(url=self._get_version_endpoint('user', 'email', email), headers=self._get_signed_headers())
        else:
            raise ClientException("Please provide the username or email address.")

        try:
            return r.json()
        except Exception:
            return self._error(r)

    ## Order endpoints
    ## ------------

    def create_order(self, username, digital_pricing=[], print_pricing=[], combo_pricing=[], billing_address={},
                     shipping_address={}, label=None):
        """
        Order creation endpoint for third-party processed orders
        POST /v1/order/external/

        args: username (str), digital_pricing (list <pricing_id>), print_pricing (list <print_option_id>) <opt>,
              combo_pricing (list <print_option_id>) <opt>, billing_address (dict), shipping_address (dict), label (str) <opt>

        notes: This endpoint allows the creation of orders in one step, bypassing the typical checkout system.  The
               endpoint should only be used for 'forcing' in orders where the collection of funds and order fulfillment
               process is handled by the integration partner.  Requires the 'create_orders' scope and management
               permission for the associated white label (if provided).
        """
        payload = {'username': username, 'digital_pricing': digital_pricing, 'billing_address': billing_address,
                   'shipping_address': shipping_address, 'label': label}
        request_data = self._get_request_data(payload)
        r = requests.post(url=self._get_version_endpoint('order', 'external'), data=request_data, headers=self._get_signed_headers(payload))

        try:
            return r.json()
        except Exception:
            return self._error(r)

    def order(self, id):
        """
        Order endpoint
        GET /v1/order/

        args: id (int)
        """
        r = requests.get(url=self._get_version_endpoint('order', id), headers=self._get_signed_headers())

        try:
            return r.json()
        except Exception:
            return self._error(r)

    ## Store endpoints
    ## ------------

    def create_cart(self, username=None, digital_pricing=[], print_pricing=[], combo_pricing=[], label=None):
        """
        Cart creation endpoint
        POST /v1/cart/

        args: username (string) <opt>,  digital_pricing (list <pricing_id>), print_pricing (list <print_option_id>) <opt>,
              combo_pricing (list <print_option_id>) <opt>, label (string) <opt>

        returns: token for the new cart.
                 user can be sent to redshelf.com/cart/?t=<token> to assign the cart or if username is provided the
                 cart will be assigned automatically
        """

        payload = {'username': username, 'digital_pricing': digital_pricing}
        request_data = self._get_request_data(payload)
        r = requests.post(url=self._get_version_endpoint('cart'), data=request_data, headers=self._get_signed_headers(payload))

        try:
            return r.json()
        except Exception:
            return self._error(r)

    ## Misc / help endpoints
    ## ------------

    def describe(self):
        """
        V1 Describe endpoint
        GET /v1/describe/
        """
        r = requests.get(url=self._get_version_endpoint('describe'), headers=self._get_signed_headers())

        try:
            return r.json()
        except Exception:
            return self._error(r)


## #################
## Support functions
## #################

def format_address(first_name=None, last_name=None, full_name=None, company_name=None, line_1=None,
                   line_2=None, city=None, state=None, postal_code=None, country=None):
    """
    Helper function for creating API safe addresses.
    """
    addr = {}

    ## parse single field names
    if full_name and not first_name and not last_name:
        n_list = unicode(full_name).strip().split()
        first_name = n_list[0]
        last_name = n_list[len(n_list) - 1]

    if not postal_code:
        raise ClientException('Postal code is required.')

    if not first_name:
        raise ClientException('First name is required.')

    if not last_name:
        raise ClientException('Last name is required.')

    ## clean data for transit and do some basic validation
    addr.update({'first_name': first_name, 'last_name': last_name})

    if company_name:
        company_name = unicode(company_name).strip()

    if line_1:
        line_1 = unicode(line_1).strip()

    if line_2:
        line_2 = unicode(line_2).strip()

    if city:
        city = unicode(city).strip()

    if state:
        state = unicode(state).strip()
        if len(state) > 3:
            raise ClientException('State code is not valid.')

    if postal_code:
        postal_code = unicode(postal_code).strip()
        if len(postal_code) > 12:
            raise ClientException('Postal code is not valid.')

    if country:
        country = unicode(country).strip()
        if len(country) > 2:
            raise ClientException('Country code should only be two digits.')

    addr.update({'company_name': company_name, 'line_1': line_1, 'line_2': line_2, 'city': city,
                 'state': state, 'postal_code': postal_code, 'country': country})
    return addr


class ClientException(Exception):
    pass