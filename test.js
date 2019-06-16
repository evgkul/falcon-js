var lib = require('./src/index.js');

(async function(){
    var key = await lib.generateKeyPair([0],9,0);
    console.log(key.private.length);
    var sign = await lib.sign(key.private,[0,1,0]);
    //console.log('sign',sign);
    var vrfy = await lib.verify(key.public,[0,1,0],sign.signature,sign.nonce);
    console.log('verify',vrfy);
})()