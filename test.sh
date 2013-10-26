time python crypto.py en crypto.py;
time python crypto.py de out.crypto -o out.tst;
md5 crypto.py out.tst;
rm out.crypto;
rm out.tst;
