var c_api = require('./compiled.js');
var crypto = require('crypto');

//var keygen = null;
//var max_pub = 0;
//var max_priv = 0;
var size_t_size = 0;
var sign_p = 0;
var rand_p = 0;
var vrfy_p = 0;

var malloc;
var free;

ready = new Promise(function(resolve,reject){
    c_api.onRuntimeInitialized = function(){
        size_t_size = c_api._size_t_size();
        sign_p = c_api._falcon_sign_new();
        vrfy_p = c_api._falcon_vrfy_new();
        malloc = c_api._malloc;
        free = c_api._free;

        rand_p = malloc(40);
        //console.log('ready',size_t_size,sign_p);
        resolve();
    }
})

var parseSizedArray = function(m){
    var size = new Uint32Array(c_api.HEAPU8.slice(m,m+4).buffer)[0];
    return c_api.HEAPU8.slice(m+4,m+4+size);
}

var generateKeyPair = async function(seed_inp,logn,ternary){
    await ready;
    var keygen = c_api._falcon_keygen_new(logn,ternary);
    var max_priv = c_api._falcon_keygen_max_privkey_size(keygen);
    var max_pub = c_api._falcon_keygen_max_pubkey_size(keygen);
    var prbuffer = c_api._malloc(max_priv);
    var pubuffer = c_api._malloc(max_pub);
    var prsize = c_api._malloc(size_t_size);
    var pusize = c_api._malloc(size_t_size);
    c_api.setValue(prsize,max_priv,'i32');
    c_api.setValue(pusize,max_pub,'i32');
    var seed = c_api._malloc(256);
    c_api.HEAPU8.set(seed_inp,seed);
    c_api._falcon_keygen_set_seed(keygen,seed,256,1);
    var code = c_api._falcon_keygen_make(keygen,1,prbuffer,prsize,pubuffer,pusize);
    var res;
    if(code==1){
        var pr_array = c_api.HEAPU8.slice(prbuffer,prbuffer+c_api.getValue(prsize,'i32'));
        var pu_array = c_api.HEAPU8.slice(pubuffer,pubuffer+c_api.getValue(pusize,'i32'));
        res = {
            priv: pr_array,
            pub: pu_array
        }
    }

    c_api._free(prbuffer);
    c_api._free(pubuffer);
    c_api._free(prsize);
    c_api._free(pusize);
    //c_api._free(max_priv);
    //c_api._free(max_pub);
    c_api._free(seed);
    c_api._falcon_keygen_free(keygen)
    if(res==null) throw 'Unable to generate keys!';
    return res;
}

var sign = async function(privkey,data){
    await ready;

    c_api.HEAPU8.set(crypto.randomBytes(40),rand_p);
    c_api._falcon_sign_set_seed(sign_p,rand_p,40,1);

    var key_p = malloc(privkey.length);
    c_api.HEAPU8.set(privkey,key_p);
    var w = c_api._falcon_sign_set_private_key(sign_p,key_p,privkey.length);
    //console.log('pk',w);

    var nonce = crypto.randomBytes(40);
    var nonce_p = malloc(40);
    c_api.HEAPU8.set(nonce,nonce_p);
    c_api._falcon_sign_start_external_nonce(sign_p,nonce_p,40);
    
    var data_p = malloc(data.length);
    c_api.HEAPU8.set(data,data_p);
    c_api._falcon_sign_update(sign_p,data_p,data.length);
    var sign_res = malloc(2049);
    var size = c_api._falcon_sign_generate(sign_p,sign_res,2049,1);
    //console.log('size',size);
    var res = c_api.HEAPU8.slice(sign_res,sign_res+size);
    free(nonce_p);
    free(data_p);
    free(sign_res);
    free(key_p);
    return {
        signature: res,
        nonce: nonce
    }
    //console.log('start',i);
}

var verify = async function(pubkey,data,signature,nonce){
    await ready;
    var pubkey_p = malloc(pubkey.length);
    c_api.HEAPU8.set(pubkey,pubkey_p);
    var data_p = malloc(data.length);
    c_api.HEAPU8.set(data,data_p);
    var signature_p = malloc(signature.length);
    c_api.HEAPU8.set(signature,signature_p);
    var nonce_p = malloc(nonce.length);
    c_api.HEAPU8.set(nonce,nonce_p);

    var r = 0;
    r = c_api._falcon_vrfy_set_public_key(vrfy_p,pubkey_p,pubkey.length);
    //console.log('pkey',r);
    if(r!=1) throw 'Invalid public key!';
    c_api._falcon_vrfy_start(vrfy_p,nonce_p,nonce.length);
    //console.log('nonce',r);
    c_api._falcon_vrfy_update(vrfy_p,data_p,data.length);
    r = c_api._falcon_vrfy_verify(vrfy_p,signature_p,signature.length);
    free(pubkey_p);
    free(data_p);
    free(signature_p);
    free(nonce_p);
    return r;
}

module.exports = {
    generateKeyPair: generateKeyPair,
    sign: sign,
    verify: verify
}