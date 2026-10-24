#include <string>
#include <cstring>

char *get_TLS_SNI(unsigned char *bytes, int* len)
{
    if (bytes == NULL || len == NULL || *len < 44)
        return NULL;

    const unsigned char *ebytes = bytes + *len;
    unsigned char sidlen = bytes[43];
    const unsigned char *curr = bytes + 44 + sidlen;

    if (curr + 2 > ebytes) return NULL;
    unsigned short cslen = ((unsigned short)curr[0] << 8) | curr[1];
    curr += 2 + cslen;

    if (curr + 1 > ebytes) return NULL;
    unsigned char cmplen = *curr;
    curr += 1 + cmplen;

    if (curr + 2 > ebytes) return NULL;
    unsigned short ext_total_len = ((unsigned short)curr[0] << 8) | curr[1];
    curr += 2;

    const unsigned char *maxchar = curr + ext_total_len;
    if (maxchar > ebytes) maxchar = ebytes;

    static thread_local std::string tls_sni_storage;
    while (curr + 4 <= maxchar)
    {
        unsigned short ext_type = ((unsigned short)curr[0] << 8) | curr[1];
        unsigned short ext_len = ((unsigned short)curr[2] << 8) | curr[3];
        curr += 4;

        if (curr + ext_len > maxchar) break;

        if (ext_type == 0) // SNI
        {
            if (ext_len >= 5 && curr[2] == 0)
            {
                unsigned short namelen = ((unsigned short)curr[3] << 8) | curr[4];
                if (5 + namelen <= ext_len && namelen > 0 && namelen < 1024)
                {
                    tls_sni_storage.assign(reinterpret_cast<const char*>(curr + 5), namelen);
                    *len = static_cast<int>(tls_sni_storage.length());
                    return const_cast<char*>(tls_sni_storage.c_str());
                }
            }
            return NULL;
        }
        curr += ext_len;
    }
    return NULL;
}
