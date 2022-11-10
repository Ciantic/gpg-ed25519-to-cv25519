# Example how to use PKDECRYPT and PKSIGN in gpg-agent

`run.sh` creates temporary GNUPGHOME directory, with a ED25519 cert/signing key, and cv25519 encryption key.
Then it encrypts with raw ECDH values, and signs with hash algorithm.

To see this in action look at the generated gpg-agent.log, for completeness example output are below.

Explanation of the variables for `ecc_sign` and `ecc_decrypt` are in GnuPG's Libgcrypt [ecc.c source code](https://github.com/gpg/libgcrypt/blob/ccfa9f2c1427b40483984198c3df41f8057f69f8/cipher/ecc.c#L888-L915)

## Example encryption in the log file:

```
ecc_decrypt info: Montgomery/Standard
ecc_decrypt name: Curve25519
ecc_decrypt    p:+7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
ecc_decrypt    a:+01db41
ecc_decrypt    b:+01
ecc_decrypt  g.X:+09
ecc_decrypt  g.Y:+5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14
ecc_decrypt  g.Z:+01
ecc_decrypt    n:+1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
ecc_decrypt    h:+08
ecc_decrypt    q: [264 bit]
                  40366988d95018c909f00b5a7f116a700ba84d4938e9328bce966c6b6ee09c61 \
                  14
ecc_decrypt    d:+57c956e252f4ea5c6279fa2a144d8440d94095e76e38117e2680ebbf42928e78
ecc_decrypt  d_e: [72 bit]
                  3a3132333431323334
ecc_decrypt    kG.X:+34333231343332313a
ecc_decrypt    kG.Y:+00
ecc_decrypt    kG.Z:+01
ecc_decrypt  res: [264 bit]
                  40f87edeea1bb394c3d5835f53fd8415f57be65ccd0dd793ac07f87985e7a8ac \
                  4e
ecc_decrypt    => Success
```

## Example signin in the log file:

```
ecc_sign info: Edwards/Ed25519+EdDSA
ecc_sign name: Ed25519
ecc_sign    p:+7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
ecc_sign    a:+7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec
ecc_sign    b:+52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
ecc_sign  g.X:+216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
ecc_sign  g.Y:+6666666666666666666666666666666666666666666666666666666666666658
ecc_sign  g.Z:+01
ecc_sign    n:+1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
ecc_sign    h:+08
ecc_sign    q: [264 bit]
               451b491e4e74e22ff06efdb9109 \
               29
ecc_sign    d: [256 bit]
               de25530bbc65a094a287332324daf7cf90d2e24df92257e847776fb1a17c0d11
ecc_sign   data: [128 bit]
                 12345678901234567890123456789014
  e_pk: f7af6e23f22cd265312663738961b603e89451b491e4e74e22ff06efdb910929
     m: 12345678901234567890123456789014
     r: 61caa9d4562cf9d43a544b95e71feb510cb6035b6f6ccdbbc4c57581063ceb6d \
        e923565b5e9d2422b43d4c11483e59541603417e2788779704436f7d6bf83cd4
   r.x:+39f52e02888056c91ba968c927f133456265fb0356cfa90d7243507b9c457380
   r.y:+39752fc037164d7ef8ed08efa4f4df404234f984db931b047d4289c30fd5bded
   e_r: edbdd50fc389427d041b93db84f9344240dff4a4ef08edf87e4d1637c02f7539
 H(R+): 3859ae3d9ff0aaab3766c5749ece61ecedea2081ad0c0c2034e78e472167fb60 \
        d34263f9dd74b7cdd3cfa64b36841003d0f89076def5fb7ae14558e5733d49ad
   e_s: 781a5ffc9686ac541bfeaeb5f53e4c66f7d01d94a1315239d52aa6a7a2107807
ecc_sign      => Success
```
