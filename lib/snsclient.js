var https = require('https')
  , crypto = require('crypto')
  , url = require('url');

var winston = require('winston');

// Local memory cache for PEM certificates
var pem_cache = {};

// keys required in a valid SNS request
var REQUIRED_KEYS = [
    'Type', 'MessageId', 'TopicArn', 'Message', 'Timestamp'
  , 'SignatureVersion', 'Signature', 'SigningCertURL'
];

function validateRequest(opts, message, cb) {
    // Let's make sure all keys actually exist to avoid errors
    for(var i=0; i<REQUIRED_KEYS.length; i++) {
        if(!(REQUIRED_KEYS[i] in message)){
            winston.error('AWS SNS message missing key: '+REQUIRED_KEYS[i]);
            return cb(new Error('Invalid request'));
        }
    }

    // short circuit to be able to bypass validation
    if('verify' in opts && opts.verify === false) return cb();

    var cert = url.parse(message.SigningCertURL)
      , arn = message.TopicArn.split(':');
    
    // TopicArn Format:  arn:aws:sns:{{ region }}:{{ account }}:{{ topic }}
    if(opts.region  && opts.region  !== arn[3]) {
        winston.error('AWS SNS message expected region '+opts.region+', got '+arn[3]);
        return cb(new Error('Invalid request'));
    }
    if(opts.account && opts.account !== arn[4]) {
        winston.error('AWS SNS message expected account '+opts.account+', got '+arn[4]);
        return cb(new Error('Invalid request'));
    }
    if(opts.topic   && opts.topic   !== arn[5]) {
        winston.error('AWS SNS message expected topic '+opts.topic+', got '+arn[5]);
        return cb(new Error('Invalid request'));
    } 

    // Make sure the certificate comes from the same region
    var expectedUrl ='sns.'+arn[3]+'.amazonaws.com' 
    if(cert.host !== expectedUrl) {
        winston.error('AWS SNS message cert URL expected '+expectedUrl+', got '+cert.host);
        return cb(new Error('Invalid request'));
    }

    // check if certificate has been downloaded before and cached
    if(message.SigningCertURL in pem_cache) {
        var pem = pem_cache[message.SigningCertURL];
        return validateMessage(pem, message, cb);
    } else {
        https.get(cert, function(res) {
            var chunks = [];
            res.on('data', function(chunk) {
                chunks.push(chunk);
            });
            res.on('end', function() {
                var pem = chunks.join('');
                pem_cache[message.SigningCertURL] = pem;
                return validateMessage(pem, message, cb);
            });
            res.on('error', function() {
                return cb(new Error('Could not download certificate.'));
            });
        });
    }
}

function validateMessage(pem, message, cb) {
    var msg = buildSignatureString(message);
    if(!msg) {
        winston.error('AWS SNS message signature string was empty.');
        return cb(new Error('Invalid request'));
    }

    var verifier = crypto.createVerify('RSA-SHA1');
    verifier.update(msg, 'utf8');
    if (verifier.verify(pem, message.Signature, 'base64')) {
        return cb();
    } else {
        winston.error('AWS SNS failed crypto signature validation.');
        return cb(new Error('Invalid request'));
    }
}

function buildSignatureString(message) {
    var chunks = [];
    if(message.Type === 'Notification') {
        chunks.push('Message');
        chunks.push(message.Message);
        chunks.push('MessageId');
        chunks.push(message.MessageId);
        if(message.Subject) {
            chunks.push('Subject');
            chunks.push(message.Subject);
        }
        chunks.push('Timestamp');
        chunks.push(message.Timestamp);
        chunks.push('TopicArn');
        chunks.push(message.TopicArn);
        chunks.push('Type');
        chunks.push(message.Type);
    } else if(message.Type === 'SubscriptionConfirmation') {
        chunks.push('Message');
        chunks.push(message.Message);
        chunks.push('MessageId');
        chunks.push(message.MessageId);
        chunks.push('SubscribeURL');
        chunks.push(message.SubscribeURL);
        chunks.push('Timestamp');
        chunks.push(message.Timestamp);
        chunks.push('Token');
        chunks.push(message.Token);
        chunks.push('TopicArn');
        chunks.push(message.TopicArn);
        chunks.push('Type');
        chunks.push(message.Type);
    } else { return false; }

    return chunks.join('\n')+'\n';
}

function SNSClient(opts, cb) {
    // opts is entirely optional, but cb is not
    if(typeof opts === 'function') {
        cb = opts;
        opts = {};
    }
    return function SNSClient(req, res) {
        var chunks = [];
        req.on('data', function(chunk) {
            chunks.push(chunk);
        });
        req.on('end', function() {
            var message;
            try {
                message = JSON.parse(chunks.join(''));
            } catch(e) {
                // catch a JSON parsing error
                winston.error('AWS SNS got invalid JSON: '+e);
                return cb(new Error('Error parsing JSON'), null, res);
            }
            validateRequest(opts, message, function(err){
                if(err) {
                    winston.error('AWS SNS error from validateRequest:: '+err);
                    return cb(err, null, res);
                }
                if(message.Type === 'SubscriptionConfirmation') {
                    var request = https.get(url.parse(message.SubscribeURL), function (res) {
                        winston.info('SNSClient confirmed subsciption. result: '+res.statusCode);
                    }).on('error', function (e) {
                        winston.error('SNSClient error confirming subscription: '+e);
                    });
                    res.end();
                    return;
                }
                if(message.Type === 'Notification') {
                    return cb(null, message, res);
                }
            });
        });
    };
}


module.exports = SNSClient;
