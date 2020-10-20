const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,//이메일 중복 방지
    required: true
  },
  password: {
    type: String,
    required: true
  }
});

userSchema.pre('save', function(next){
  const user = this;
  if (!user.isModified('password')) {
    return next();//inside of middleware
  }

  bcrypt.genSalt(10, (err, salt) => {
    if (err){
      return next(err);
    }

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});
//function쓰는 이유는 우리가 (user instance)tuser가 저장하고자 하는 정보를 this로 쓸건데
//() => 어레이 펑션을 쓰면 this가 context inside this file이 된대

userSchema.methods.comparePassword = function(candidatePassword) {
  const user = this;
  
  return new Promise((resolve, reject) => {
    bcrypt.compare(candidatePassword, user.password, (err, isMatch) => {
      if (err) {
        return reject(err);
      } 

      if (!isMatch){
        return reject(false);
      }
      
      resolve(true);
    });
  });
};

mongoose.model('User', userSchema);