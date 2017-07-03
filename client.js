console.log('Begin device flow...');

var request = require('request');
var inquirer = require('inquirer');

function recoverAccount(mfaToken) {
  var otpQuestion = [
    {
        type: 'input',
        name: 'code',
        message: 'Recovery Code?',
    }
  ]
  
  inquirer.prompt(otpQuestion).then(function (answers) {
      // Use user feedback for... whatever!!
      console.log(answers)
  
      postLookup(answers.code, mfaToken);
  });
}

function enrollAuthenticator(mfaToken) {
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    mfa_token: mfaToken
  };
  
  
  request.post('http://127.0.0.1:8084/associate', { body: JSON.stringify(form), headers: {'content-type': 'application/json'} }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log('-- ENROLL RESPONSE');
    console.log(res.statusCode);
    console.log(body);
    console.log('---')
    
    var json = JSON.parse(body);
    
    var qrImage = 'https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=' + encodeURIComponent(json.barcode_uri);
    console.log('QR IMAGE:');
    console.log(qrImage)
    
    confirmEnrollment(mfaToken, json.bind_code)
  });
}

function confirmEnrollment(mfaToken, bindCode) {
  pollEnrollment(mfaToken, bindCode)
}

function pollEnrollment(mfaToken, bindCode) {
  
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    mfa_token: mfaToken,
    bind_code: bindCode
  };
  
  
  request.post('http://127.0.0.1:8084/bind', { body: JSON.stringify(form), headers: {'content-type': 'application/json'} }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log('-- ENROLL RESPONSE');
    console.log(res.statusCode);
    console.log(body);
    console.log('---')
    
    var json = JSON.parse(body);
    if (json.error == 'operation_pending') {
      console.log('PENDING, WATING...');
      
      setTimeout(function() { pollEnrollment(mfaToken, bindCode); }, 3000);
    }
  });
  
}

function challengeAuthenticator(mfaToken) {
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    mfa_token: mfaToken
  };
  
  var otpQuestion = [
    {
        type: 'input',
        name: 'otp',
        message: 'OTP Code?',
    }
  ]
  
  var cnfQuestion = [
    {
        type: 'input',
        name: 'secret',
        message: 'Secret sent to device?',
    }
  ]
  
  
  request.post('http://127.0.0.1:8084/challenge', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log('-- INIT RESPONSE');
    console.log(res.statusCode);
    console.log(body);
    console.log('---')
    
    var json = JSON.parse(body);
    
    if (json.error == 'enrollment_required') {
      console.log('MUST ENROLL!');
      enrollAuthenticator(mfaToken)
      return;
    }
    
    
    if (json.challenge_type == 'otp') {
      inquirer.prompt(otpQuestion).then(function (answers) {
          // Use user feedback for... whatever!!
          console.log(answers)
      
          postOTP(answers.otp, mfaToken);
      });
    } else {
      if (json.binding_method == 'prompt') {
        inquirer.prompt(cnfQuestion).then(function (answers) {
            // Use user feedback for... whatever!!
            console.log(answers)
      
            pollStatus(json.oob_code, mfaToken, answers.secret);
        });
      } else {
        pollStatus(json.oob_code, mfaToken);
      }
      
      
      
    }
    
    //pollStatus(json.push_code);
    
    
  });
}


function exchangePassword(username, password) {
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    grant_type: 'password',
    username: username,
    password: password
  };
  
  request.post('http://127.0.0.1:8082/token', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log(res.statusCode);
    console.log(body);
    //return;
    
    var json = JSON.parse(body);
    if (json.error == 'mfa_required') {
      console.log('DO MFA NOW!');
      challengeAuthenticator(json.mfa_token);
      //recoverAccount(json.mfa_token);
    }
    
    
  })
}


exchangePassword('jared.hanson', 'K8LP7TdqJfZkbD');
//enrollAuthenticator('xxxxx');
//confirmEnrollment('xxxxx');
return;



function postLookup(code, mfaToken) {
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    grant_type: 'http://auth0.com/oauth/grant-type/mfa-recovery-code',
    recovery_code: code,
    mfa_token: mfaToken
  };
  
  request.post('http://127.0.0.1:8082/token', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log(res.statusCode);
    console.log(body);
    
  })
}

function postOTP(otp, mfaToken) {
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    grant_type: 'http://auth0.com/oauth/grant-type/mfa-otp',
    otp: otp,
    mfa_token: mfaToken
  };
  
  request.post('http://127.0.0.1:8082/token', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log(res.statusCode);
    console.log(body);
    
  })
}


function pollStatus(txid, mfaToken, secret) {
  
  var form = {
    client_id: '1',
    client_secret: 'kq61yrn2lknnvri',
    grant_type: 'http://auth0.com/oauth/grant-type/mfa-oob',
    oob_code: txid,
    mfa_token: mfaToken
  };
  
  if (secret) {
    form.binding_code = secret;
  }
  
  console.log('!!! POLLING STATUS....');
  
  request.post('http://127.0.0.1:8082/token', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log(res.statusCode);
    console.log(body);
    
    
    var json = JSON.parse(body);
    if (json.error == 'authorization_pending') {
      console.log('PENDING, WATING...');
      
      setTimeout(function() { pollStatus(txid, mfaToken); }, 3000);
    }
    
  })
  
}


//pollStatus('57b1b00c-7e6c-4c46-b488-d0817820e4fa');

//return;

request.get('http://127.0.0.1:8084/authenticators', function(err, res, body) {
  console.log(err);
  if (!res) { return; }
  
  console.log(res.statusCode);
  console.log(body);
  
  var creds = JSON.parse(body).credentials;
  
  
  var form = {
    method: 'otp'
  };
  
  var otpQuestion = [
    {
        type: 'input',
        name: 'otp',
        message: 'OTP Code?',
    }
  ]
  
  var cnfQuestion = [
    {
        type: 'input',
        name: 'secret',
        message: 'Secret sent to device?',
    }
  ]
  
  
  request.post('http://127.0.0.1:8084/' + creds[0].id + '/init', { form: form }, function(err, res, body) {
    console.log(err);
    if (!res) { return; }
  
    console.log('-- INIT RESPONSE');
    console.log(res.statusCode);
    console.log(body);
    console.log('---')
    
    var json = JSON.parse(body);
    
    
    if (json.mfa_type == 'otp') {
      inquirer.prompt(otpQuestion).then(function (answers) {
          // Use user feedback for... whatever!!
          console.log(answers)
      
          postOTP(answers.otp);
      });
    } else {
      if (json.binding_method == 'prompt') {
        inquirer.prompt(cnfQuestion).then(function (answers) {
            // Use user feedback for... whatever!!
            console.log(answers)
      
            pollStatus(json.oob_code, answers.secret);
        });
      } else {
        pollStatus(json.oob_code);
      }
      
      
      
    }
    
    //pollStatus(json.push_code);
    
    
  })
  
  
})
