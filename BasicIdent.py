import random
from sage.crypto.cryptosystem import PublicKeyCryptosystem
from sage.all import EllipticCurve
from sage.all import Hom
from sage.all import Zmod, FiniteField, Integer
from copy import deepcopy

class BasicIdent(PublicKeyCryptosystem):
    """
    The Basic Identity Scheme proposed by Boneh and Franklin. 
    This scheme needs an Elliptic Curve over a finite field, a point of order n, and a distortion map.
    
    PARAMETERS:
        
        * ec: An elliptic curve over a finite field.
        * P: A point of finite order.
        * dmap: A distortion map
        * (Optional) order: Order of P.
        * (Optional) pairing: Which pairing will be used? "weil" (default) or "tate".
        * (Optional) k: Embedding degree of P in ec.
        * (Optional) seed: Seed to generate pseudorandom integers (by default it will use the default option of random.seed)
    """
    
    def __init__(self, ec, P = None, dmap = None, order = None, pairing="weil", k = None, seed=None):
        self.ec = ec
        self.P = P

        self.distortion = self._deco(dmap)
        if dmap == None:
            self.distortion = self._ext

        if order == None:
            self.order = P.order()
        else:
            self.order = order

        self.pairing = pairing

        ord = self.ec.base_ring().cardinality()
        if k == None:
            k = Zmod(self.order)(ord).multiplicative_order()
        self.k = k

        random.seed(seed)
        self.t = random.randint(2, self.order-1)

        base = FiniteField(ord**self.k, 'b')
        self.hom = Hom(self.ec.base_ring(), base)(base.gen()**((ord**self.k-1)/(ord-1)))
        self.ec2 = EllipticCurve(map(int,self.ec.a_invariants())).change_ring(base)
        
    def _ext(self, P):
        # P is a point of E(F_q), and it should be of E(F_q^k)

        return self.ec2(map(self.hom, P))
        
    def _deco(self, map):
        def distortionmap(P):
            P = self._ext(P)
            return map(P)
        return distortionmap
        
    def H1(self, ID):
        try:
            mult = int(ID) % (self.order - 2)
        except:
            mult = 0
            for let in ID:
                mult = mult*256 % (self.order - 2)
                mult = (mult + ord(let)) % (self.order - 2)
        return (2+mult)*self.P
        
    def H2(self, element, length = 0):
        random.seed(hash(element))
        mask = [None]*length
        for i in xrange(length):
            mask[i] = random.choice([0, 1])
        return mask
            
    def _mask(self, message, element):
        mask = self.H2(element, len(message))
        cmsg = deepcopy(message)
        for i in xrange(len(message)):
            cmsg[i] = (message[i] + mask[i]) % 2
        return "".join(map(str,cmsg))
        
    def public_key(self, ID):
        return [self.H1(ID), self.t*self.P]
        
    def private_key(self, ID):
        return self.t*self.H1(ID)
        
    def encrypt(self, message, pubkey, seed=None, text=False):
        random.seed(seed)
        
        tmp = None
        if not text:
            tmp = Integer(message).digits(2)
        else:
            tmp = 0
            for let in message:
                tmp = tmp*256
                tmp = (tmp + ord(let))
                
            tmp = Integer(tmp).digits(2)
            
        tmp.reverse()

        r = random.randint(2, self.order-1)
        if self.pairing == "tate":
            pair = self._ext(pubkey[0]).tate_pairing(self.distortion(pubkey[1]), self.order, self.k, self.ec2.base_ring().cardinality())
        else:
            pair = self._ext(pubkey[0]).weil_pairing(self.distortion(pubkey[1]), self.order)
        
        print "Sin cifrar", tmp
        return r*self.P, self._mask(tmp, pair**r)
        
    def decrypt(self, ciphertext, privatekey, text=False):
        if self.pairing == "tate":
            pair = self._ext(privatekey).tate_pairing(self.distortion(ciphertext[0]), self.order, self.k, self.ec2.base_ring().cardinality())
        else:
            pair = self._ext(privatekey).weil_pairing(self.distortion(ciphertext[0]), self.order)
            
        msg = int(self._mask(map(int, list(ciphertext[1])), pair), base=2)
        if text:
            msg = map(chr, Integer(msg).digits(256))
            msg.reverse()
            msg = "".join(msg)
        return msg