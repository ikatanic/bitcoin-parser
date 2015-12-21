Bitcoin block-chain parser
==========================

Written as a part of my bachelor thesis.
It parses given Bitcoin chain blocks and prints out some statistics about them.

How to use
----------

```
g++ --std=c++0x parser.cpp SHA256.cpp -o parser
./parser B
```

where B is an integer, files ```blocks/blk0000X.dat``` will be parsed, where ```0 <= X < B```.


