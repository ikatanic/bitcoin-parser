// Parser bitcoin lanca blokova
// analizira graf korisnika i ispisuje statistike
// Koristenje: ./parser <B>
// B je cijeli broj, parser ce obraditi datoteke blk0000X.dat, gdje je 0 <= X < B
// datoteke se moraju nalaziti u direktoriju blocks/

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <cmath>
#include "SHA256.h"

using namespace std;

#define FOR(i, a, b) for (int i = (a); i < (b); ++i)
#define REP(i, n) FOR(i, 0, n)
#define TRACE(x) cout << #x << " = " << x << endl
#define _ << " _ " <<

typedef long long llint;

const uint32_t DELIM = 0xd9b4bef9;

const int MAXLEN = 1000000; // max duljina bloka
const int MAXN = 300000; // max broj blokova
const int MAXT = 10000000; // max broj transakcija

struct input {
  int prev_tx;
  uint32_t index;
};

struct output {
  uint64_t value;
  int address;
};

struct hash_t { 
  uint8_t a[32];
  static int cmp(const hash_t &a, const hash_t &b) {
    REP(i, 32)
      if (a.a[i] != b.a[i]) return a.a[i] < b.a[i] ? 1 : -1;
    return 0;
  }
};

struct address_t {
  uint8_t a[20];
  friend bool operator < (const address_t &a, const address_t &b) {
    REP(i, 20)
      if (a.a[i] != b.a[i]) return a.a[i] < b.a[i];
    return false;
  }
  friend bool operator == (const address_t &a, const address_t &b) {
    REP(i, 20)
      if (a.a[i] != b.a[i]) return false;
    return true;
  }
  void print() {
    REP(i, 20) printf("%02x", a[i]);
    printf("\n");
  }
};

struct block {
  hash_t hash;
  hash_t prev;
  hash_t merkle;
  uint32_t timestamp;
  uint32_t target;
  uint32_t nonce;
  uint64_t tx_cnt;
  vector<int> tx;
} b[MAXN]; // 40 MB

struct transaction {
  hash_t hash;
  vector<input> inputs;
  vector<output> outputs;
  int indeg, outdeg;
} t[MAXT];

int n = 0;
int m = 0;

int total_input = 0;
int total_output = 0;

bool publicKeyToAddress(const uint8_t in[65], address_t &out) {
  if (in[0] != 0x04) return false;
  uint8_t hash[32], tmp[25];
  computeSHA256(in, 65, hash);
  tmp[0] = 0;
  computeRIPEMD160(hash, 32, tmp+1);
  computeSHA256(tmp, 21, hash);
  computeSHA256(hash, 32, hash);
  memcpy(tmp+21, hash, 4);
  memcpy(out.a, tmp+1, 20);
  return true;
}

uint64_t readVariableInteger(uint8_t* &a) {
  uint8_t x;
  memcpy(&x, a, 1); a += 1;
  
  if (x < 0xfd) return x;
  if (x == 0xfd) {
    uint16_t ans;
    memcpy(&ans, a, 2); a += 2;
    return ans;
  }
  if (x == 0xfe) {
    uint32_t ans;
    memcpy(&ans, a, 4); a += 4;
    return ans;
  }
  uint64_t ans;
  memcpy(&ans, a, 8); a += 8;
  return ans;
}

vector<address_t> addresses;
vector<int> freq;

void parseBlock(uint8_t *a, int len) {
  block &r = b[n++];
  
  computeSHA256(a, 80, r.hash.a);
  computeSHA256(r.hash.a, 32, r.hash.a);

  a += 4; // format version
  memcpy(&r.prev, a, 32); a += 32;
  memcpy(&r.merkle, a, 32); a += 32;
  memcpy(&r.timestamp, a, 4); a += 4; 
  memcpy(&r.target, a, 4); a += 4;
  memcpy(&r.nonce, a, 4); a += 4;
  
  r.tx_cnt = readVariableInteger(a);
  r.tx.resize(r.tx_cnt);
  
  REP(tx_i, (int)r.tx_cnt) {
    int id = m++;
    r.tx[tx_i] = id;
    transaction &p = t[id];
    
    uint64_t inp_cnt, out_cnt;
    uint8_t *start = a;

    a += 4; // transaction version number

    inp_cnt = readVariableInteger(a);    
    p.inputs.resize(inp_cnt);

    REP(inp_i, (int)inp_cnt) {
      a += 32; // prev tx hash
      a += 4; // t_ind
      a += readVariableInteger(a); // script
      a += 4; // seq number = 0xffffffff
    }
    total_input += inp_cnt;


    out_cnt = readVariableInteger(a);
    p.outputs.resize(out_cnt);

    REP(out_i, (int)out_cnt) {
      uint64_t val;

      memcpy(&val, a, 8); a += 8;
      p.outputs[out_i].value = val;

      auto len = readVariableInteger(a); // script
      if (len == 25 || len == 67) {
        address_t address;
        if (len == 25) {
          memcpy(address.a, a+3, 20);
          addresses.push_back(address);
        } else {
          if (publicKeyToAddress(a+1, address)) addresses.push_back(address);
        }
      }
      a += len;
    }
    total_output += out_cnt;

    uint32_t lock_time;
    memcpy(&lock_time, a, 4); a += 4;

    computeSHA256(start, (a-start), p.hash.a);
    computeSHA256(p.hash.a, 32, p.hash.a);
  }
}

int p[MAXT]; 
int pm;

void sortTransactions() {
  REP(i, m) p[i] = i;
  sort(p, p + m, [] (const int &x, const int &y) {
      return hash_t::cmp(t[x].hash, t[y].hash) == 1;
    }
  );
  
  pm = 0;
  REP(i, m)
    if (pm == 0 || hash_t::cmp(t[p[i]].hash, t[p[pm-1]].hash))
      p[pm++] = p[i];
}

int getTxId(hash_t hash) {
  int lo = 0, hi = pm-1;
  while (lo < hi) {
    int mid = (lo + hi)/2;
    if (hash_t::cmp(t[p[mid]].hash, hash) == 1) lo = mid+1; else
      hi = mid;
  }

  int id = p[lo];
  assert(0 <= id && id < m);
  assert(hash_t::cmp(hash, t[id].hash) == 0);
  return id;
}

void sortAddresses() {
  auto &a = addresses;
  sort(a.begin(), a.end());
  a.erase(unique(a.begin(), a.end()), a.end());
}

int getAddressId(address_t a) {
  int id = (lower_bound(addresses.begin(), addresses.end(), a) - addresses.begin());
  assert(0 <= id && id < (int)addresses.size());
  return id;
}

void resolvePrevs(uint8_t *a, int len) {
  static int cur_b = 0, cur_t = 1;
  block &r = b[cur_b++];
  
  a += 80; // block prefix
  int tx_cnt = readVariableInteger(a);
  assert((int)tx_cnt == (int)r.tx_cnt);

  REP(tx_i, (int)tx_cnt) {
    transaction &p = t[cur_t++];
    
    uint64_t inp_cnt, out_cnt;

    a += 4; // transaction version number
    inp_cnt = readVariableInteger(a);
    assert((int)inp_cnt == (int)p.inputs.size());
    
    REP(inp_i, (int)inp_cnt) {
      uint32_t t_ind;
      hash_t prev_tx;
      
      memcpy(prev_tx.a, a, 32); a += 32; // tx hash
      memcpy(&t_ind, a, 4); a += 4;

      p.inputs[inp_i] = {getTxId(prev_tx), t_ind};

      a += readVariableInteger(a); // script
      a += 4; // seq number = 0xffffffff
    }

    out_cnt = readVariableInteger(a);
    assert((int)out_cnt == (int)p.outputs.size());
    REP(out_i, (int)out_cnt) {
      int &id = p.outputs[out_i].address;
      id = -1;
      a += 8; // skip value

      auto len = readVariableInteger(a); // script
      if (len == 25 || len == 67) {
        address_t address;
        if (len == 25) {
          memcpy(address.a, a+3, 20);
          id = getAddressId(address);
        } else {
          if (publicKeyToAddress(a+1, address)) {
            id = getAddressId(address);
          }
        }
      }
      a += len;
    }
    a += 4;
  }
}

void parseFiles(vector<string> files) {
  for (string filename: files) {
    FILE *file = fopen(filename.c_str(), "rb");
    
    if (!file) {
      printf("ne mogu otvorit datoteku %s\n", filename.c_str());
      exit(1);
    }
    
    uint32_t cur = 0;
    while (fread(&cur, 4, 1, file)) {
      assert(cur == DELIM);
      
      uint32_t len;
      fread(&len, 4, 1, file);
      assert(len < MAXLEN);

      static uint8_t buffer[MAXLEN];
      fread(&buffer, len, 1, file);
      parseBlock(buffer, len);
    }
    fclose(file); 
  }
  
  sortTransactions();
  sortAddresses();

  for (string filename: files) {
    FILE *file = fopen(filename.c_str(), "rb");
    
    if (!file) {
      printf("ne mogu otvorit datoteku %s\n", filename.c_str());
      exit(1);
    }
    
    uint32_t cur = 0;
    while (fread(&cur, 4, 1, file)) {
      assert(cur == DELIM);
      
      uint32_t len;
      fread(&len, 4, 1, file);

      static uint8_t buffer[MAXLEN];
      fread(&buffer, len, 1, file);
      resolvePrevs(buffer, len);
    }
    fclose(file); 
  }
}

vector<int> dad;

int findset(int x) {
  int s = x;
  while (dad[s] != s) s = dad[s];
  while (x != s) {
    int t = dad[x];
    dad[x] = s;
    x = t;
  }
  return dad[x];
}

void merge(int x, int y) {
  x = findset(x);
  y = findset(y);
  dad[y] = x;
}

vector< vector<int> > user;
vector<int> user_one_address;

void unionFind() {
  int n = addresses.size();
  dad.resize(n);
  REP(i, n) dad[i] = i;  
  freq.resize(n, 0);

  REP(i, m) {
    int cur = -1;
    for (input inp: t[i].inputs) {
      int ti = inp.prev_tx;
      int ind = inp.index;
      assert(0 <= ti && ti < m);
      if (ind < 0 || ind >= (int)t[ti].outputs.size()); else {
        int address = t[ti].outputs[ind].address;
        if (address == -1) continue;
        freq[address]++;
        if (cur == -1) cur = address;
        merge(cur, address);
      }
    }
  }
  
  vector<int> id(n, -1);
  int cnt = 0;
  REP(i, n) {
    dad[i] = findset(i);
    if (dad[i] == i) id[i] = cnt++;
  }

  user.resize(cnt);
  user_one_address.resize(cnt);

  REP(i, n) {
    if (dad[i] == i) user_one_address[id[i]] = i;
    dad[i] = id[dad[i]];
    user[dad[i]].push_back(i);
  }
  REP(i, n) {
    int &u_add = user_one_address[dad[i]];
    if (freq[i] > freq[u_add]) u_add = i;
  }
}


vector<bool> bio;

void printStats() {
  int n_blocks = ::n;
  int n = addresses.size();
  int u = user.size();
  
  uint64_t total_btc = 0;
  REP(i, m)
    if (t[i].inputs.size() == 1) {
      if (t[i].inputs[0].prev_tx != 0) continue;
      for (output out: t[i].outputs)
        total_btc += out.value;
    }

  bio.resize(u);
  total_btc /= 1e8;
  
  printf("Timestamp zadnjeg bloka: %d\n", (int)b[n_blocks-1].timestamp);
  printf("Ukupan broj blokova: %d\n", n_blocks);
  printf("Ukupan broj BTC u sustavu %llu\n", (unsigned long long)total_btc);
  printf("Ukupan broj inputa: %d\n", total_input);
  printf("Ukupan broj outputa: %d\n", total_output);
  printf("Ukupan broj transakcija: %d\n", m);
  printf("Ukupan broj adresa: %d\n", n);
  printf("Ukupan broj korisnika: %d\n", u);
  printf("\n");
  
  // posiljatelji
  REP(i, u) 
    bio[i] = false;
  REP(i, m)
    for (input inp: t[i].inputs) {
      int ti = inp.prev_tx;
      int ind = inp.index;
      if (ind >= 0 && ind < (int)t[ti].outputs.size()) {
        int address = t[ti].outputs[ind].address;
        if (address == -1) continue;
        bio[dad[address]] = true;
      }
    }
  
  int sender_cnt = 0;
  REP(i, u)
    sender_cnt += bio[i];
  printf("Broj korisnika koji su nesto poslali %d\n", sender_cnt);
  
  // distribucija broja adresa po korisniku
  printf("\nDistribucija broja adresa po korisniku:\n");
  vector<int> f = {-1, 1, 2, 5, 10, 50, 100, 500, 1000, 10000, 100000, 200000, 500000, 1000000, 1000000000};
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, u)
      if (lo <= (int)user[j].size() && (int)user[j].size() <= hi) cnt++;
    printf("[%d, %d] -> %d\n", lo, hi, cnt);
  }
  
  // top 10 po broju adresa
  printf("\nTop 10 po broju adresa\n");
  vector<int> pos(u, 0);
  REP(i, u) pos[i] = i;
  partial_sort(pos.begin(), pos.begin() + 10, pos.end(), [] (const int &x, const int &y) {
      return user[x].size() > user[y].size();
    }
  );

  REP(i, 10) {
    int x = pos[i];
    printf("%d. broj adresa = %d -> jedna od adresa ", i+1, (int)user[x].size());
    addresses[user_one_address[x]].print();
  }

  vector<uint64_t> income(u, 0);
  vector<uint64_t> balance(u, 0);
  vector<int> indeg(u, 0);
  vector<int> outdeg(u, 0);

  REP(i, m) {
    for (input inp: t[i].inputs) {
      int ti = inp.prev_tx;
      int ind = inp.index;
      if (ind >= 0 && ind < (int)t[ti].outputs.size()) {
        int address = t[ti].outputs[ind].address;
        if (address == -1) continue;
        int x = dad[address];
        outdeg[x]++;
        balance[x] -= t[ti].outputs[ind].value;
      }
    }
    for (output out: t[i].outputs) {
      if (out.address == -1) continue;
      int x = dad[out.address];
      indeg[x]++;
      balance[x] += out.value;
      income[x] += out.value;
    }
  }

  REP(i, u) {
    balance[i] /= 1e8;
    income[i] /= 1e8;
  }

  // income
  printf("\nTotal income:\n");
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, u)
      if (lo <= (int)income[j] && (int)income[j] <= hi) cnt++;
    printf("[%d, %d] -> %d\n", lo, hi, cnt);
  }
  partial_sort(pos.begin(), pos.begin() + 10, pos.end(), [&] (const int &x, const int &y) {
      return income[x] > income[y];
    }
  );
  printf("Top 10:\n");
  REP(i, 10) {
    int x = pos[i];
    printf("%d. income = %d -> adresa = ", i+1, (int)income[x]);
    addresses[user_one_address[x]].print();
  }

  // balance
  printf("\nBalance:\n");
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, u)
      if (lo <= (int)balance[j] && (int)balance[j] <= hi) cnt++;
    printf("[%d, %d] -> %d\n", lo, hi, cnt);
  }
  partial_sort(pos.begin(), pos.begin() + 10, pos.end(), [&] (const int &x, const int &y) {
      return balance[x] > balance[y];
    }
  );
  printf("Top 10:\n");
  REP(i, 10) {
    int x = pos[i];
    printf("%d. balance = %d -> adresa = ", i+1, (int)balance[x]);
    addresses[user_one_address[x]].print();
  }


  // outdeg
  printf("\nOut deg:\n");
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, u)
      if (lo <= (int)outdeg[j] && (int)outdeg[j] <= hi) cnt++;
    printf("[%d, %d] -> %d\n", lo, hi, cnt);
  }
  partial_sort(pos.begin(), pos.begin() + 10, pos.end(), [&] (const int &x, const int &y) {
      return outdeg[x] > outdeg[y];
    }
  );
  printf("Top 10:\n");
  REP(i, 10) {
    int x = pos[i];
    printf("%d. outdeg = %d -> adresa = ", i+1, outdeg[x]);
    addresses[user_one_address[x]].print();
  }


  // indeg
  printf("\nIn deg:\n");
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, u)
      if (lo <= (int)indeg[j] && (int)indeg[j] <= hi) cnt++;
    printf("[%d, %d] -> %d\n", lo, hi, cnt);
  }
  partial_sort(pos.begin(), pos.begin() + 10, pos.end(), [&] (const int &x, const int &y) {
      return indeg[x] > indeg[y];
    }
  );
  REP(i, 10) {
    int x = pos[i];
    printf("%d. indeg = %d -> adresa = ", i+1, (int)indeg[x]);
    addresses[user_one_address[x]].print();
  }

  // iznosi transakcija
  printf("\nDistribucija iznosa transakcija:\n");
  f = {-1, 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
  FOR(i, 1, (int)f.size()) {
    int lo = f[i-1]+1, hi = f[i];
    int cnt = 0;
    REP(j, m)
      for (output out: t[j].outputs) {
        int val = out.value / 1e6;
        if (lo <= val && val <= hi) cnt++;
      }
    printf("[%.2lf, %.2lf] -> %d\n", lo/100.0, hi/100.0, cnt);
  }

}

int main(int argc, char **argv) {
  if (argc != 2) {
    puts("Uputa: ./parser <B>");
    exit(-1);
  }

  int B = stoi(argv[1]);

  vector<string> files;
  REP(i, B) {
    char name[20];
    sprintf(name, "blocks/blk%05d.dat", i);
    files.push_back(name);
  }

  REP(i, 32) t[0].hash.a[i] = 0;
  m++; // zero hash transaction
  
  parseFiles(files);

  unionFind();
  
  printStats();

  return 0;
}
