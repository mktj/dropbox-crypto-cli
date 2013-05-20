time python crypto.py en crypto.py;
time python crypto.py de test.txt -o out.tst;
md5 crypto.py out.tst;
rm test.txt;
rm out.tst;
