const express = require('express');
const mongoose = require('mongoose');

const app = express();

const mongoUri = 'mongodb+srv://admin:Wkdnfla11*^^*@cluster0.hy9sz.mongodb.net/<dbname>?retryWrites=true&w=majority';

mongoose.connect(mongoUri, {
  useUnifiedTopology:true,
  useNewUrlParser: true,
  useCreateIndex: true
});
mongoose.connection.on('connected', () => {
  console.log('Connected to mongo instance');
});
mongoose.connection.on('error', () => {
  console.error('Error connecting to mongo', err);
});

app.get('/', (req, res) => {
  res.send('Hi there!');
});

app.listen(3000, () => {
  console.log('Listening on port 3000');
});

