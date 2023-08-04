use std::collections::HashMap;

use libzeropool::{native::params::PoolParams, fawkes_crypto::{ff_uint::{Num, PrimeField}, rand::Rng, native::{ecc::{JubJubParams, EdwardsPoint}, poseidon::{PoseidonParams, poseidon}}}};

use crate::{random::CustomRng, merkle::Hash};



#[derive(Debug)]
pub struct ShareProof<P: PoolParams> {
    r_x: Num<P::Fr>,
    mu: Num<P::Fs>
}


#[derive(Debug)]
pub struct KeyGenRound1<P: PoolParams> {
    from_identifier: u32,
    sigma:  ShareProof<P>,
    commitment: Vec<Num<P::Fr>>
}

pub struct KeyGenRound2<P: PoolParams> {
    from_identifier: u32,
    share: Num<P::Fs>
}

#[derive(Debug)]
pub struct SignRound1<P: PoolParams> {
    from_identifier: u32,
    d: Num<P::Fr>, // D
    e: Num<P::Fr> // E
}

impl<P: PoolParams> SignRound1<P> {
    pub fn hash(&self, poseidon_params: &PoseidonParams<P::Fr>) -> Num<P::Fr> {
        poseidon(&[Num::from(self.from_identifier), self.d, self.e], poseidon_params)
    }
}

#[derive(Clone)]
pub struct Nonce<P: PoolParams> {
    d: Num<P::Fs>, // d
    e: Num<P::Fs>, // e
}


#[derive(Default)]
pub struct FrostParticipant<P: PoolParams> {
    identifier: u32,
    t: u32, // threshold
    n: u32, // total number of participants

    a: Option<Vec<Num<P::Fs>>>, // coefs
    commitments: HashMap<u32, Vec<Num<P::Fr>>>, // commitments
    shares: HashMap<u32, Num<P::Fs>>, // shares
    sk: Option<Num<P::Fs>>, // participant secret key
    pk: Option<Num<P::Fr>>, // common public key

    nonce: Option<Nonce<P>>,
}

impl<P: PoolParams> FrostParticipant<P> {
    pub fn new(identifier: u32, t: u32, n: u32) -> FrostParticipant<P> {
        FrostParticipant {
            identifier,
            t,
            n,
            a: None,
            commitments: HashMap::new(),
            shares: HashMap::new(),
            sk: None,
            pk: None,
            nonce: None,
        }
    }

    pub fn keygen_round_1(&mut self, params: &P) -> KeyGenRound1<P> {
        let mut rng = CustomRng;
        // step 1
        let a: Vec<Num<P::Fs>> = (0..self.t).map(|_| rng.gen()).collect();
        self.a = Some(a.clone());

        // step 2
        let k: Num<P::Fs> = rng.gen();
        let g = params.jubjub().edwards_g();
        let r = g.mul(k, params.jubjub());
        
        let a_0_x = g.mul(a[0], params.jubjub()).x;
        let r_x = r.x;

        // TODO: params.note() should work for now, but it is definetly not ok
        let c = Self::hash_keygen(self.identifier, Num::ONE, a_0_x, r_x, params.note()).to_other_reduced();

        let mu = k + a[0] * c;
        let sigma = ShareProof {
            r_x,
            mu
        };

        // step 3
        let commitment: Vec<_> = a.iter().map(|a| g.mul(*a, params.jubjub()).x).collect();
        self.commitments.insert(self.identifier, commitment.clone());

        // step 4
        KeyGenRound1 { 
            from_identifier: self.identifier, 
            sigma, 
            commitment, 
        }
    }

    pub fn keygen_round_1_receive(&mut self, message: &KeyGenRound1<P>, params: &P) {
        let g = params.jubjub().edwards_g();

        let commitment = message.commitment.clone();
        let c_0 = EdwardsPoint::subgroup_decompress(commitment[0], params.jubjub()).unwrap();
        let r = EdwardsPoint::subgroup_decompress(message.sigma.r_x, params.jubjub()).unwrap();
        let mu = message.sigma.mu;

        // TODO: params.note() should work for now, but it is definetly not ok
        let c = Self::hash_keygen(message.from_identifier, Num::ONE, commitment[0], r.x, params.note()).to_other_reduced();

        let left = g.mul(mu, params.jubjub());
        let right = r.add(&c_0.mul(c, params.jubjub()), params.jubjub());
        if left != right {
            panic!("proof is not correct");
        }
        
        self.commitments.insert(message.from_identifier, commitment);
    }

    pub fn keygen_round_2(&mut self, to_identifier: u32) -> KeyGenRound2<P> {
        // step 1
        let mut share = Num::ZERO;
        let mut x = Num::ONE;
        let a  = self.a.clone().unwrap();
        for i in 0..self.t {
            share += a[i as usize] * x;
            x *= Num::from(to_identifier);
        }

        KeyGenRound2 { 
            from_identifier: self.identifier, 
            share, 
        }
    }

    pub fn keygen_round_2_receive(&mut self, message: &KeyGenRound2<P>, params: &P) {
        // step 2
        let g = params.jubjub().edwards_g();
        let commitment = self.commitments[&message.from_identifier].clone();
        let left = g.mul(message.share, params.jubjub());

        let mut right = EdwardsPoint::zero();
        let mut x = Num::ONE;
        for i in 0..self.t {
            let c = EdwardsPoint::subgroup_decompress(commitment[i as usize], params.jubjub()).unwrap();
            right = right.add(&c.mul(x, params.jubjub()), params.jubjub());
            x *= Num::from(self.identifier);
        }

        if left != right {
            panic!("share is not valid");
        }

        self.shares.insert(message.from_identifier, message.share);
    }

    pub fn keygen_round_2_complete(&mut self, params: &P) {
        let mut sk = Num::ZERO;
        for (_, v) in &self.shares {
            sk += v;
        }
        self.shares.clear();
        self.sk = Some(sk);

        let mut pk = EdwardsPoint::zero();
        for i in 1..=self.n {
            let c_0  = EdwardsPoint::subgroup_decompress(self.commitments[&i][0], params.jubjub()).unwrap();
            pk = pk.add(&c_0, params.jubjub());
        }
        self.pk = Some(pk.x);
    }

    pub fn sign_round_1(&mut self, params: &P) -> SignRound1<P> {
        let mut rng = CustomRng;
        let g = params.jubjub().edwards_g();

        let d: Num<P::Fs> = rng.gen();
        let d_pub = g.mul(d, params.jubjub());
        let e: Num<P::Fs> = rng.gen();
        let e_pub = g.mul(e, params.jubjub());
        self.nonce = Some(Nonce{ d, e });
        SignRound1 { 
            from_identifier: self.identifier, 
            d: d_pub.x, 
            e: e_pub.x 
        }
    }

    pub fn sign_round_2(&mut self, m: Num<P::Fr>, b: &Vec<SignRound1<P>>, params: &P) -> (Num<P::Fr>, Num<P::Fs>) {
        // TODO: validate m and b
        let mut r = EdwardsPoint::zero();
        for b_i in b {
            let rho = Self::hash_rho(b_i.from_identifier, m, b, params).to_other_reduced();
            let d_i = EdwardsPoint::subgroup_decompress(b_i.d, params.jubjub()).unwrap();
            let e_i = EdwardsPoint::subgroup_decompress(b_i.e, params.jubjub()).unwrap();

            let r_i = d_i.add(&e_i.mul(rho, params.jubjub()), params.jubjub());
            r = r.add(&r_i, params.jubjub());
        }

        let c = poseidon(&[r.x, self.pk.clone().unwrap(), m], params.eddsa());

        // compute lagrange coefficient
        let mut l: Num<P::Fs> = Num::ONE;
        for b_i in b {
            if b_i.from_identifier == self.identifier {
                continue;
            }
            l *= Num::from(b_i.from_identifier) / (Num::from(b_i.from_identifier) - Num::from(self.identifier));
        }

        let d = self.nonce.clone().unwrap().d;
        let e = self.nonce.clone().unwrap().e;

        let rho = Self::hash_rho(self.identifier, m, &b, params);
        let z = d + e * rho.to_other_reduced() + l * self.sk.clone().unwrap() * c.to_other_reduced();

        (r.x, z)
    }

    fn hash_keygen<F: PrimeField>(
        identifier: u32,
        context_string: Num<F>, // TODO: what should it be?
        a_0_x: Num<F>,
        r_x: Num<F>,
        poseidon_params: &PoseidonParams<F>,
    ) -> Num<F> {
        let identifier = Num::from(identifier);
        poseidon(&[identifier, context_string, a_0_x, r_x], poseidon_params)
    }

    fn hash_rho(
        identifier: u32,
        m: Num<P::Fr>,
        b: &Vec<SignRound1<P>>,
        params: &P,
    ) -> Num<P::Fr> {
        // TODO: figure out how to do it correctly
        let mut b_acc = b[0].hash(params.eddsa());
        for i in 1..b.len() {
            b_acc = poseidon(&[b_acc, b[i].hash(params.eddsa())], params.compress());
        }

        poseidon(&[Num::from(identifier), m, b_acc], params.eddsa())
    }
}


#[cfg(test)]
mod tests {
    use libzeropool::{native::params::{PoolBN256, PoolParams}, POOL_PARAMS, fawkes_crypto::{rand::Rng, ff_uint::Num, native::eddsaposeidon::eddsaposeidon_verify}};

    use crate::random::CustomRng;

    use super::FrostParticipant;


    #[test]
    fn test_frost() {
        let params = &*POOL_PARAMS;

        let t = 2_u32;
        let n = 3_u32;
        let mut participants: Vec<_> = (1..4).map(|i| FrostParticipant::<PoolBN256>::new(i, t, n)).collect();

        // round 1
        for i in 0..n {
            let message = participants[i as usize].keygen_round_1(params);
            for j in 0..n {
                if i == j {
                    continue;
                }
                participants[j as usize].keygen_round_1_receive(&message, params);
            }
        }

        // round 2
        for i in 0..n {
            for j in 0..n {
                let message = participants[i as usize].keygen_round_2(j + 1);
                participants[j as usize].keygen_round_2_receive(&message, params);
            }
        }

        for i in 0..n {
            participants[i as usize].keygen_round_2_complete(params);
        }

        // SIGNATURE

        // round 1
        let signers_set = [0, 2];
        let pk = participants[0].pk.clone().unwrap();
        let mut b = vec![];
        for i in signers_set {
            b.push(participants[i].sign_round_1(params));
        }

        // round 2
        // TODO: implement all aggregator stuff
        let mut rng = CustomRng;
        let m = rng.gen();
        let mut partial_signatures = vec![];
        for i in signers_set {
            partial_signatures.push(participants[i].sign_round_2(m, &b, params));
        }

        let r = partial_signatures[0].0;
        let mut s = Num::ZERO;
        for ps in partial_signatures {
            s += ps.1;
        }

        println!("{}", eddsaposeidon_verify(s, r, pk, m, params.eddsa(), params.jubjub()));
        assert!(eddsaposeidon_verify(s, r, pk, m, params.eddsa(), params.jubjub()))
    }
}