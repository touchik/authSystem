/*
 * auth_client.cpp — Auth Client v4.0
 *
 * Фичи:
 *   - ECDH X25519 + AES-256-GCM шифрование всех запросов
 *   - HWID привязка (MAC + CPU + OS — сложно подделать)
 *   - Онлайн-пинг каждые 5 минут (сервер может мгновенно отозвать доступ)
 *   - Автоматический re-handshake при истечении сессии
 *
 * Сборка Linux/macOS:
 *   g++ -O2 -std=c++17 auth_client.cpp -lcurl -lssl -lcrypto -o auth_client
 *
 * Сборка Windows:
 *   g++ -O2 -std=c++17 auth_client.cpp -lcurl -lssl -lcrypto -lws2_32 -o auth_client.exe
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <functional>
#include <sys/stat.h>
#include <curl/curl.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <iphlpapi.h>
#  pragma comment(lib, "iphlpapi.lib")
#else
#  include <termios.h>
#  include <unistd.h>
#  include <sys/utsname.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  if defined(__linux__)
#    include <netpacket/packet.h>
#  elif defined(__APPLE__)
#    include <net/if_dl.h>
#  endif
#endif

// ─────────────────────────────────────────────────────────────────────────────
// BASE64
// ─────────────────────────────────────────────────────────────────────────────
static const std::string B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64Enc(const std::vector<uint8_t>& in) {
    std::string out; int i = 0; uint8_t a3[3], a4[4];
    for (uint8_t b : in) {
        a3[i++] = b;
        if (i == 3) {
            a4[0]=(a3[0]&0xfc)>>2; a4[1]=((a3[0]&3)<<4)|((a3[1]&0xf0)>>4);
            a4[2]=((a3[1]&0xf)<<2)|((a3[2]&0xc0)>>6); a4[3]=a3[2]&0x3f;
            for(int j=0;j<4;j++) out+=B64[a4[j]]; i=0;
        }
    }
    if (i) {
        for(int j=i;j<3;j++) a3[j]=0;
        a4[0]=(a3[0]&0xfc)>>2; a4[1]=((a3[0]&3)<<4)|((a3[1]&0xf0)>>4);
        a4[2]=((a3[1]&0xf)<<2)|((a3[2]&0xc0)>>6);
        for(int j=0;j<i+1;j++) out+=B64[a4[j]];
        while(i++<3) out+='=';
    }
    return out;
}

static std::vector<uint8_t> b64Dec(const std::string& in) {
    std::vector<uint8_t> out; int i=0; uint8_t a3[3],a4[4];
    for(char c:in) {
        if(c=='=') break;
        auto p=B64.find(c); if(p==std::string::npos) continue;
        a4[i++]=(uint8_t)p;
        if(i==4){
            a3[0]=(a4[0]<<2)|((a4[1]&0x30)>>4);
            a3[1]=((a4[1]&0xf)<<4)|((a4[2]&0x3c)>>2);
            a3[2]=((a4[2]&3)<<6)|a4[3];
            for(int j=0;j<3;j++) out.push_back(a3[j]); i=0;
        }
    }
    if(i) {
        for(int j=i;j<4;j++) a4[j]=0;
        a3[0]=(a4[0]<<2)|((a4[1]&0x30)>>4);
        a3[1]=((a4[1]&0xf)<<4)|((a4[2]&0x3c)>>2);
        for(int j=0;j<i-1;j++) out.push_back(a3[j]);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON HELPERS
// ─────────────────────────────────────────────────────────────────────────────
static std::string je(const std::string& s) {
    std::string o;
    for(unsigned char c:s){
        if(c=='"') o+="\\\""; else if(c=='\\') o+="\\\\";
        else if(c=='\n') o+="\\n"; else if(c=='\r') o+="\\r"; else o+=c;
    }
    return o;
}
static std::string jget(const std::string& j, const std::string& k) {
    std::string s = "\"" + k + "\":\"";
    auto p = j.find(s);
    if (p == std::string::npos) {
        // попробуем с пробелом после двоеточия
        s = "\"" + k + "\": \"";
        p = j.find(s);
        if (p == std::string::npos) return "";
    }
    p += s.size();
    // читаем до закрывающей кавычки, пропуская \escaped
    std::string result;
    while (p < j.size()) {
        if (j[p] == '\\' && p + 1 < j.size()) {
            char nx = j[p+1];
            if      (nx == '"')  { result += '"';  p += 2; }
            else if (nx == '\\') { result += '\\'; p += 2; }
            else if (nx == 'n')  { result += '\n';  p += 2; }
            else                 { result += j[p++]; }
        } else if (j[p] == '"') {
            break;
        } else {
            result += j[p++];
        }
    }
    return result;
}
static std::string extractError(const std::string& b) {
    std::string m=jget(b,"detail");
    return m.empty()?(b.empty()?"нет ответа":b.substr(0,120)):m;
}

// ─────────────────────────────────────────────────────────────────────────────
// HWID — уникальный отпечаток железа
// ─────────────────────────────────────────────────────────────────────────────
static std::string getHWID() {
    std::string raw;

#if defined(_WIN32)
    // MAC-адрес первого адаптера
    IP_ADAPTER_INFO buf[16]; DWORD sz = sizeof(buf);
    if (GetAdaptersInfo(buf, &sz) == ERROR_SUCCESS) {
        char mac[32];
        snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
                 buf[0].Address[0], buf[0].Address[1], buf[0].Address[2],
                 buf[0].Address[3], buf[0].Address[4], buf[0].Address[5]);
        raw += mac;
    }
    // Имя компьютера
    char name[256]; DWORD nlen = sizeof(name);
    if (GetComputerNameA(name, &nlen)) raw += name;
    // Версия Windows
    OSVERSIONINFOA vi{}; vi.dwOSVersionInfoSize = sizeof(vi);
    GetVersionExA(&vi);
    raw += std::to_string(vi.dwMajorVersion) + "." + std::to_string(vi.dwMinorVersion);

#else
    // MAC-адрес через getifaddrs
    struct ifaddrs* ifa = nullptr;
    getifaddrs(&ifa);
    for (auto* i = ifa; i; i = i->ifa_next) {
        if (!i->ifa_addr) continue;
#  if defined(__linux__)
        if (i->ifa_addr->sa_family == AF_PACKET) {
            auto* s = (struct sockaddr_ll*)i->ifa_addr;
            if (s->sll_halen == 6) {
                char mac[32];
                snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
                         s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                         s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                raw += mac; break;
            }
        }
#  elif defined(__APPLE__)
        if (i->ifa_addr->sa_family == AF_LINK) {
            auto* s = (struct sockaddr_dl*)i->ifa_addr;
            if (s->sdl_alen == 6) {
                unsigned char* m = (unsigned char*)LLADDR(s);
                char mac[32];
                snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
                         m[0],m[1],m[2],m[3],m[4],m[5]);
                raw += mac; break;
            }
        }
#  endif
    }
    if (ifa) freeifaddrs(ifa);

    // uname (имя хоста + версия ОС)
    struct utsname u{};
    if (uname(&u) == 0) {
        raw += std::string(u.nodename) + u.sysname + u.release;
    }
#endif

    if (raw.empty()) raw = "unknown-hwid";

    // SHA-256 → hex строка (32 байта = 64 символа)
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((uint8_t*)raw.data(), raw.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP
// ─────────────────────────────────────────────────────────────────────────────
static size_t curlW(void* d,size_t s,size_t n,std::string* o){o->append((char*)d,s*n);return s*n;}
struct Resp{long code=0;std::string body,err;};
static std::string g_server;

static Resp httpReq(const std::string& path,const std::string& body="",const std::string& method="GET"){
    Resp res; CURL* c=curl_easy_init();
    if(!c){res.err="curl init";return res;}
    struct curl_slist* h=nullptr;
    h=curl_slist_append(h,"Content-Type: application/json");
    h=curl_slist_append(h,"Accept: application/json");
    char eb[CURL_ERROR_SIZE]={};
    curl_easy_setopt(c,CURLOPT_URL,(g_server+path).c_str());
    curl_easy_setopt(c,CURLOPT_HTTPHEADER,h);
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,curlW);
    curl_easy_setopt(c,CURLOPT_WRITEDATA,&res.body);
    curl_easy_setopt(c,CURLOPT_ERRORBUFFER,eb);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,15L);
    curl_easy_setopt(c,CURLOPT_CONNECTTIMEOUT,5L);
    curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(c,CURLOPT_SSL_VERIFYPEER,0L);
    if(method=="POST") curl_easy_setopt(c,CURLOPT_POSTFIELDS,body.c_str());
    CURLcode rc=curl_easy_perform(c);
    if(rc==CURLE_OK) curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&res.code);
    else res.err=eb[0]?eb:curl_easy_strerror(rc);
    curl_slist_free_all(h); curl_easy_cleanup(c);
    return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// ECDH X25519
// ─────────────────────────────────────────────────────────────────────────────
struct ECDHKeys {
    EVP_PKEY* priv=nullptr; std::vector<uint8_t> pub_raw;
    ECDHKeys(){
        EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,nullptr);
        EVP_PKEY_keygen_init(ctx); EVP_PKEY_keygen(ctx,&priv); EVP_PKEY_CTX_free(ctx);
        size_t len=32; pub_raw.resize(32);
        EVP_PKEY_get_raw_public_key(priv,pub_raw.data(),&len);
    }
    ~ECDHKeys(){if(priv)EVP_PKEY_free(priv);}
    ECDHKeys(const ECDHKeys&)=delete;
    ECDHKeys& operator=(const ECDHKeys&)=delete;
    std::vector<uint8_t> exchange(const std::vector<uint8_t>& peer) const {
        EVP_PKEY* pk=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,nullptr,peer.data(),peer.size());
        EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(priv,nullptr);
        EVP_PKEY_derive_init(ctx); EVP_PKEY_derive_set_peer(ctx,pk);
        size_t slen=32; std::vector<uint8_t> s(slen);
        EVP_PKEY_derive(ctx,s.data(),&slen);
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pk); return s;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HKDF-SHA256
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> hkdf(const std::vector<uint8_t>& secret){
    std::vector<uint8_t> key(32);
    EVP_KDF* kdf=EVP_KDF_fetch(nullptr,"HKDF",nullptr);
    EVP_KDF_CTX* ctx=EVP_KDF_CTX_new(kdf); EVP_KDF_free(kdf);
    const char* info="auth-server-v2";
    OSSL_PARAM p[]={
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,(char*)"SHA256",0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,(void*)secret.data(),secret.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,(void*)info,strlen(info)),
        OSSL_PARAM_END
    };
    EVP_KDF_derive(ctx,key.data(),key.size(),p); EVP_KDF_CTX_free(ctx);
    return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM
// ─────────────────────────────────────────────────────────────────────────────
struct EncR{std::vector<uint8_t> nonce,ct;};

static EncR aesEnc(const std::vector<uint8_t>& key,const std::string& plain){
    EncR r; r.nonce.resize(12); RAND_bytes(r.nonce.data(),12);
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_EncryptInit_ex(ctx,nullptr,nullptr,key.data(),r.nonce.data());
    std::vector<uint8_t> ct(plain.size()+16); int len=0,tot=0;
    EVP_EncryptUpdate(ctx,ct.data(),&len,(uint8_t*)plain.data(),(int)plain.size()); tot=len;
    EVP_EncryptFinal_ex(ctx,ct.data()+tot,&len); tot+=len;
    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag.data());
    EVP_CIPHER_CTX_free(ctx);
    ct.resize(tot); ct.insert(ct.end(),tag.begin(),tag.end());
    r.ct=std::move(ct); return r;
}

static std::string aesDec(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& nonce,
                           const std::vector<uint8_t>& ct_tag){
    if(ct_tag.size()<16) throw std::runtime_error("Ответ слишком короткий");
    size_t clen=ct_tag.size()-16;
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);
    EVP_DecryptInit_ex(ctx,nullptr,nullptr,key.data(),nonce.data());
    std::vector<uint8_t> plain(clen); int len=0;
    EVP_DecryptUpdate(ctx,plain.data(),&len,ct_tag.data(),(int)clen);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,(void*)(ct_tag.data()+clen));
    int ok=EVP_DecryptFinal_ex(ctx,plain.data()+len,&len); EVP_CIPHER_CTX_free(ctx);
    if(ok<=0) throw std::runtime_error("GCM tag неверен");
    return std::string(plain.begin(),plain.end());
}

// ─────────────────────────────────────────────────────────────────────────────
// КРИПТО-СЕССИЯ
// ─────────────────────────────────────────────────────────────────────────────
struct CryptoSess{std::string id; std::vector<uint8_t> key; bool ready=false;};
static CryptoSess g_cs;

static bool doHandshake(){
    std::cout<<"[*] Установка шифрованного канала...\n";
    auto r1=httpReq("/secure/handshake");
    if(!r1.err.empty()||r1.code!=200){
        std::cout<<"[✗] Handshake: "<<(r1.err.empty()?extractError(r1.body):r1.err)<<"\n";
        return false;
    }
    std::string sid=jget(r1.body,"session_id"), spub=jget(r1.body,"server_pub_key");
    if(sid.empty()||spub.empty()){std::cout<<"[✗] Неверный ответ\n";return false;}
    ECDHKeys keys;
    std::string body2="{\"session_id\":\""+je(sid)+"\",\"client_pub_key\":\""+je(b64Enc(keys.pub_raw))+"\"}";
    auto r2=httpReq("/secure/handshake",body2,"POST");
    if(!r2.err.empty()||r2.code!=200){
        std::cout<<"[✗] Handshake step2: "<<(r2.err.empty()?extractError(r2.body):r2.err)<<"\n";
        return false;
    }
    g_cs={sid,hkdf(keys.exchange(b64Dec(spub))),true};
    std::cout<<"[✓] Канал зашифрован [AES-256-GCM]\n";
    return true;
}

static Resp securePost(const std::string& ep, const std::string& payload,
                       bool raw = false){
    if(!g_cs.ready){if(!doHandshake()){Resp r;r.err="Handshake failed";return r;}}
    auto enc=aesEnc(g_cs.key,payload);
    std::string body="{\"session_id\":\""+je(g_cs.id)+"\","
                      "\"nonce\":\""+je(b64Enc(enc.nonce))+"\","
                      "\"ciphertext\":\""+je(b64Enc(enc.ct))+"\"}";
    auto res=httpReq("/secure/"+ep,body,"POST");
    if(res.code==400&&res.body.find("session")<res.body.size()){
        g_cs.ready=false;
        if(!doHandshake()) return res;
        return securePost(ep,payload,raw);
    }
    // Авторасшифровка: только если не raw и ответ не содержит file_type
    if(!raw && res.code==200){
        bool is_launch = res.body.find("\"file_type\"") != std::string::npos;
        if(!is_launch){
            std::string nb=jget(res.body,"nonce"), cb=jget(res.body,"ciphertext");
            if(!nb.empty()&&!cb.empty()){
                try{ res.body=aesDec(g_cs.key,b64Dec(nb),b64Dec(cb)); }
                catch(std::exception& e){ std::cout<<"[!] Расшифровка: "<<e.what()<<"\n"; }
            }
        }
    }
    return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// СЕССИЯ ПОЛЬЗОВАТЕЛЯ + ОНЛАЙН-ПИНГ
// ─────────────────────────────────────────────────────────────────────────────
static std::string      g_token, g_username, g_hwid;
static std::atomic<bool> g_ping_running{false};
static std::thread       g_ping_thread;

static void pingLoop(int interval_sec) {
    while (g_ping_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(interval_sec));
        if (!g_ping_running.load()) break;

        std::string payload = "{\"token\":\""+je(g_token)+"\",\"hwid\":\""+je(g_hwid)+"\"}";
        auto res = securePost("ping", payload);

        if (res.code == 401 || res.code == 403) {
            std::string reason = extractError(res.body);
            std::cout << "\n\n[!] СЕССИЯ ПРЕРВАНА СЕРВЕРОМ: " << reason << "\n";
            std::cout << "[!] Программа будет закрыта...\n";
            g_ping_running = false;
            g_token.clear();
            // Здесь разработчик вызывает завершение своей программы
            std::exit(1);
        }
    }
}

static void startPing(int interval_sec = 300) {
    g_ping_running = true;
    g_ping_thread = std::thread(pingLoop, interval_sec);
    g_ping_thread.detach();
}

static void stopPing() {
    g_ping_running = false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ВВОД ПАРОЛЯ БЕЗ ECHO
// ─────────────────────────────────────────────────────────────────────────────
#if defined(_WIN32)
static std::string readPwd(){
    HANDLE h=GetStdHandle(STD_INPUT_HANDLE); DWORD m;
    GetConsoleMode(h,&m); SetConsoleMode(h,m&~ENABLE_ECHO_INPUT);
    std::string p; std::getline(std::cin,p);
    SetConsoleMode(h,m); std::cout<<"\n"; return p;
}
#else
static std::string readPwd(){
    termios o{},n{}; tcgetattr(STDIN_FILENO,&o);
    n=o; n.c_lflag&=~(tcflag_t)ECHO; tcsetattr(STDIN_FILENO,TCSANOW,&n);
    std::string p; std::getline(std::cin,p);
    tcsetattr(STDIN_FILENO,TCSANOW,&o); std::cout<<"\n"; return p;
}
#endif

// ─────────────────────────────────────────────────────────────────────────────
// UI
// ─────────────────────────────────────────────────────────────────────────────
static void ln(){std::cout<<"────────────────────────────────────\n";}
static std::string rdln(const std::string& p){
    std::cout<<p; std::string s; std::getline(std::cin,s);
    auto a=s.find_first_not_of(" \t"),b=s.find_last_not_of(" \t");
    return a==std::string::npos?"":s.substr(a,b-a+1);
}

static void doRegister(){
    ln(); std::cout<<"  РЕГИСТРАЦИЯ  [AES-256-GCM + HWID]\n"; ln();
    std::string inv=rdln("Инвайт-код      : ");
    std::string usr=rdln("Имя пользователя: ");
    std::cout<<           "Пароль          : "; std::string pwd=readPwd();

    if(inv.empty()){std::cout<<"[✗] Инвайт пустой\n";return;}
    if(usr.size()<3||usr.size()>32){std::cout<<"[✗] Имя: 3–32 символа\n";return;}
    if(pwd.size()<8){std::cout<<"[✗] Пароль минимум 8 символов\n";return;}
    if(pwd.size()>128){std::cout<<"[✗] Пароль максимум 128 символов\n";return;}

    std::string payload="{\"invite_code\":\""+je(inv)+"\","
                         "\"username\":\""+je(usr)+"\","
                         "\"password\":\""+je(pwd)+"\","
                         "\"hwid\":\""+je(g_hwid)+"\"}";

    std::cout<<"\n[*] Отправка зашифрованного запроса...\n";
    auto res=securePost("register",payload);
    if(!res.err.empty()){std::cout<<"[✗] "<<res.err<<"\n";return;}
    if(res.code==200){
        g_token=jget(res.body,"token"); g_username=jget(res.body,"username");
        std::cout<<"[✓] Успешно! Добро пожаловать, "<<g_username<<"\n";
        std::cout<<"[✓] HWID привязан к этому компьютеру\n";
        startPing(300); // пинг каждые 5 минут
    } else {
        std::cout<<"[✗] Ошибка "<<res.code<<": "<<extractError(res.body)<<"\n";
    }
}

static void doLogin(){
    ln(); std::cout<<"  ВХОД  [AES-256-GCM + HWID]\n"; ln();
    std::string usr=rdln("Имя пользователя: ");
    std::cout<<           "Пароль          : "; std::string pwd=readPwd();

    if(usr.empty()||pwd.empty()){std::cout<<"[✗] Поля не могут быть пустыми\n";return;}
    if(pwd.size()>128){std::cout<<"[✗] Пароль слишком длинный\n";return;}

    std::string payload="{\"username\":\""+je(usr)+"\","
                         "\"password\":\""+je(pwd)+"\","
                         "\"hwid\":\""+je(g_hwid)+"\"}";

    std::cout<<"\n[*] Отправка зашифрованного запроса...\n";
    auto res=securePost("login",payload);
    if(!res.err.empty()){std::cout<<"[✗] "<<res.err<<"\n";return;}
    if(res.code==200){
        g_token=jget(res.body,"token"); g_username=jget(res.body,"username");
        std::cout<<"[✓] Вход выполнен! Добро пожаловать, "<<g_username<<"\n";
        startPing(300); // пинг каждые 5 минут
    } else if(res.code==403&&res.body.find("HWID")!=std::string::npos){
        std::cout<<"[✗] Эта программа привязана к другому компьютеру\n";
        std::cout<<"    Обратитесь к администратору для сброса HWID\n";
    } else if(res.code==403&&res.body.find("BANNED")!=std::string::npos){
        std::cout<<"[✗] Ваш аккаунт заблокирован\n";
    } else {
        std::cout<<"[✗] Ошибка "<<res.code<<": "<<extractError(res.body)<<"\n";
    }
}

static void showStatus(){
    ln();
    std::cout<<"  Шифрование  : "<<(g_cs.ready?"AES-256-GCM ✓":"нет")<<"\n";
    std::cout<<"  HWID        : "<<g_hwid.substr(0,16)<<"...\n";
    if(g_token.empty()){
        std::cout<<"  Авторизация : не выполнена\n";
    } else {
        std::cout<<"  Авторизация : выполнена\n";
        std::cout<<"  Пользователь: "<<g_username<<"\n";
        std::cout<<"  Пинг сервера: каждые 5 мин ✓\n";
        std::cout<<"  Токен       : "<<g_token.substr(0,24)<<"...\n";
    }
    ln();
}


// ─────────────────────────────────────────────────────────────────────────────
// LAUNCH PAYLOAD
// Получает зашифрованный файл с сервера и запускает нужным способом
// ─────────────────────────────────────────────────────────────────────────────

#if defined(_WIN32)
#  include <windows.h>
#  include <io.h>
#  define POPEN  _popen
#  define PCLOSE _pclose
#else
#  include <sys/wait.h>
#  define POPEN  popen
#  define PCLOSE pclose
#endif
#include <fstream>

// Определяем ОС для выбора интерпретатора
#if defined(_WIN32)
static const std::string PY_CMD  = "python";
static const std::string LUA_CMD = "lua";
static const std::string SH_CMD  = "cmd /c";
static const std::string TMP_DIR = std::string(getenv("TEMP") ? getenv("TEMP") : "C:\\Temp") + "\\";
static const std::string EXE_EXT = ".exe";
#else
static const std::string PY_CMD  = "python3";
static const std::string LUA_CMD = "lua";
static const std::string SH_CMD  = "bash";
static const std::string TMP_DIR = "/tmp/";
static const std::string EXE_EXT = "";
#endif

// Расшифровываем payload отдельно (не через securePost — там другой формат ответа)
static std::vector<uint8_t> decryptPayload(
    const std::string& nonce_b64,
    const std::string& ct_b64)
{
    auto nonce = b64Dec(nonce_b64);
    auto ct    = b64Dec(ct_b64);
    if (nonce.size() != 12 || ct.size() < 16)
        throw std::runtime_error("Неверный формат payload");

    // AES-256-GCM расшифровка (переиспользуем aesDec)
    std::string plain = aesDec(g_cs.key, nonce, ct);
    return std::vector<uint8_t>(plain.begin(), plain.end());
}

// ── Установка переменных окружения для HWID проверки ─────────────────────────
static void setAuthEnv() {
    // Передаём HWID и токен скрипту через переменные окружения
    // Скрипт сверяет AUTH_HWID с железом и завершается если не совпадает
#if defined(_WIN32)
    SetEnvironmentVariableA("AUTH_HWID",    g_hwid.c_str());
    SetEnvironmentVariableA("AUTH_TOKEN",   g_token.c_str());
    SetEnvironmentVariableA("AUTH_SERVER",  g_server.c_str());
    SetEnvironmentVariableA("AUTH_USER",    g_username.c_str());
#else
    setenv("AUTH_HWID",   g_hwid.c_str(),    1);
    setenv("AUTH_TOKEN",  g_token.c_str(),   1);
    setenv("AUTH_SERVER", g_server.c_str(),  1);
    setenv("AUTH_USER",   g_username.c_str(),1);
#endif
}

// ── Запуск Python (через stdin — не пишем на диск) ───────────────────────────
static int runPython(const std::vector<uint8_t>& code) {
    std::cout << "[*] Запуск Python скрипта...\n";
    setAuthEnv();
    FILE* p = POPEN((PY_CMD + " -").c_str(), "w");
    if (!p) { std::cout << "[✗] python не найден\n"; return -1; }
    fwrite(code.data(), 1, code.size(), p);
    int rc = PCLOSE(p);
    return rc;
}

// ── Запуск Lua (через stdin) ─────────────────────────────────────────────────
static int runLua(const std::vector<uint8_t>& code) {
    std::cout << "[*] Запуск Lua скрипта...\n";
    setAuthEnv();
    FILE* p = POPEN((LUA_CMD + " -").c_str(), "w");
    if (!p) { std::cout << "[✗] lua не найден\n"; return -1; }
    fwrite(code.data(), 1, code.size(), p);
    int rc = PCLOSE(p);
    return rc;
}

// ── Запуск Shell/Batch (через stdin или временный файл) ──────────────────────
static int runShell(const std::vector<uint8_t>& code, const std::string& type) {
    setAuthEnv();
#if defined(_WIN32)
    // Batch на Windows — нужен временный файл (cmd не читает stdin как скрипт)
    std::string tmp = TMP_DIR + "~run_" + std::to_string(GetTickCount()) + ".bat";
    { std::ofstream f(tmp, std::ios::binary); f.write((char*)code.data(), code.size()); }
    std::cout << "[*] Запуск Batch скрипта...\n";
    int rc = system(("cmd /c \"" + tmp + "\"").c_str());
    remove(tmp.c_str());
    return rc;
#else
    std::cout << "[*] Запуск Shell скрипта...\n";
    FILE* p = POPEN("bash -s", "w");
    if (!p) { std::cout << "[✗] bash не найден\n"; return -1; }
    fwrite(code.data(), 1, code.size(), p);
    int rc = PCLOSE(p);
    return rc;
#endif
}

// ── Запуск EXE (временный файл → запустить → удалить) ───────────────────────
static int runExe(const std::vector<uint8_t>& code, const std::string& fname) {
#if defined(_WIN32)
    std::string tmp = TMP_DIR + "~" + fname;
#else
    std::string tmp = TMP_DIR + "~" + fname;
#endif
    setAuthEnv();
    std::cout << "[*] Записываем exe во временный файл...\n";
    { std::ofstream f(tmp, std::ios::binary); f.write((char*)code.data(), code.size()); }

#if !defined(_WIN32)
    // На Linux/macOS нужно дать права на выполнение
    chmod(tmp.c_str(), 0700);
#endif

    std::cout << "[*] Запуск " << fname << "...\n";

    // Передаём токен как аргумент чтобы exe мог проверить сессию
    std::string cmd = "\"" + tmp + "\" \"" + g_token + "\" \"" + g_server + "\"";

#if defined(_WIN32)
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cmdline = cmd;
    if (CreateProcessA(nullptr, (LPSTR)cmdline.c_str(), nullptr, nullptr,
                       FALSE, 0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        remove(tmp.c_str());
        return (int)ec;
    }
    remove(tmp.c_str());
    return -1;
#else
    int rc = system(cmd.c_str());
    remove(tmp.c_str());
    return rc;
#endif
}

// ── Главная функция запуска ──────────────────────────────────────────────────
static void doLaunch() {
    if (g_token.empty()) {
        std::cout << "[✗] Сначала выполните вход\n";
        return;
    }

    ln();
    std::cout << "  ЗАГРУЗКА ПРИЛОЖЕНИЯ  [AES-256-GCM]\n";
    ln();
    std::cout << "[*] Запрос зашифрованного файла с сервера...\n";

    // Запрашиваем payload
    std::string payload = "{\"token\":\"" + je(g_token) + "\","
                           "\"hwid\":\"" + je(g_hwid) + "\"}";
    // raw=true — ответ содержит поля payload, не нужно авторасшифровывать
    auto res = securePost("launch", payload, true);

    if (!res.err.empty()) {
        std::cout << "[✗] Ошибка сети: " << res.err << "\n";
        return;
    }
    if (res.code == 401) {
        std::cout << "[✗] Токен недействителен — войдите снова\n";
        return;
    }
    if (res.code == 403) {
        std::string r = extractError(res.body);
        if (r.find("HWID") != std::string::npos)
            std::cout << "[✗] HWID несовпадение\n";
        else if (r.find("BANNED") != std::string::npos)
            std::cout << "[✗] Аккаунт заблокирован\n";
        else
            std::cout << "[✗] Доступ запрещён: " << r << "\n";
        return;
    }
    if (res.code == 503) {
        std::cout << "[✗] Файл приложения не найден на сервере\n";
        return;
    }
    if (res.code != 200) {
        std::cout << "[✗] Ошибка " << res.code << ": " << extractError(res.body) << "\n";
        return;
    }

    // Парсим ответ
    std::string file_type = jget(res.body, "file_type");
    std::string file_name = jget(res.body, "file_name");
    std::string file_size = jget(res.body, "file_size");
    std::string nonce     = jget(res.body, "nonce");
    std::string ciphertext= jget(res.body, "ciphertext");

    if (nonce.empty() || ciphertext.empty()) {
        std::cout << "[✗] Неверный ответ сервера\n";
        return;
    }

    std::cout << "[✓] Получен файл: " << file_name
              << " [" << file_type << "] " << file_size << " байт\n";
    std::cout << "[*] Расшифровка в памяти...\n";

    // Расшифровываем
    std::vector<uint8_t> code;
    try {
        code = decryptPayload(nonce, ciphertext);
    } catch (std::exception& e) {
        std::cout << "[✗] Ошибка расшифровки: " << e.what() << "\n";
        return;
    }

    std::cout << "[✓] Расшифровано: " << code.size() << " байт\n";
    ln();

    // Определяем способ запуска
    int rc = 0;
    if (file_type == "python") {
        rc = runPython(code);
    } else if (file_type == "lua") {
        rc = runLua(code);
    } else if (file_type == "shell" || file_type == "batch") {
        rc = runShell(code, file_type);
    } else if (file_type == "exe") {
        rc = runExe(code, file_name.empty() ? "app" + EXE_EXT : file_name);
    } else {
        std::cout << "[✗] Неизвестный тип файла: " << file_type << "\n";
        return;
    }

    ln();
    if (rc == 0)
        std::cout << "[✓] Программа завершена успешно\n";
    else
        std::cout << "[!] Программа завершена с кодом: " << rc << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc,char** argv){
    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_server=(argc>1)?argv[1]:"http://127.0.0.1:8000";
    g_hwid=getHWID();

    std::cout<<"\n"
             <<"╔════════════════════════════════════════╗\n"
             <<"║  AUTH CLIENT v4.0  [ECDH+AES+HWID]    ║\n"
             <<"╚════════════════════════════════════════╝\n"
             <<"  Сервер    : "<<g_server<<"\n"
             <<"  HWID      : "<<g_hwid.substr(0,16)<<"...\n"
             <<"  Алгоритмы : X25519 / HKDF-SHA256 / AES-256-GCM\n";

    while(true){
        std::cout<<"\n";
        if(!g_token.empty()) std::cout<<"  [ "<<g_username<<" ]\n\n";
        // Пункт 5 только если авторизован
        if (g_token.empty()) {
            std::cout<<"  1. Регистрация\n  2. Вход\n  3. Статус\n  0. Закрыть\n\n  > ";
        } else {
            std::cout<<"  1. Регистрация\n  2. Вход\n  3. Статус\n  4. Выйти\n  5. Запустить программу\n  0. Закрыть\n\n  > ";
        }
        std::string ch; std::getline(std::cin,ch);
        if      (ch=="1") doRegister();
        else if (ch=="2") doLogin();
        else if (ch=="3") showStatus();
        else if (ch=="4"){
            stopPing(); g_token.clear(); g_username.clear();
            std::cout<<"[✓] Сессия завершена\n";
        }
        else if (ch=="5") doLaunch();
        else if(ch=="0"||std::cin.eof()) break;
        else std::cout<<"  [!] Неверная команда\n";
    }

    stopPing();
    curl_global_cleanup();
    std::cout<<"\nДо свидания.\n";
    return 0;
}