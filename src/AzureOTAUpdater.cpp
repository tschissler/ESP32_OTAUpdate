#include <Arduino.h>
#include "HttpsOTAUpdate.h"
#include "AzureOTAUpdater.h"

static HttpsOTAStatus_t otastatus;

// HttpsOTA may use the URL pointer beyond the call to begin();
// keep a stable copy to avoid dangling pointers (e.g., when source is an MQTT payload buffer).
static String otaUrl;

// Trusted root certificates, as concatenated PEM blocks (mbedTLS parses all of them):
// 1. DigiCert Global Root G2 - Azure Blob Storage, as defined in the Azure Portal certificate chain
//    Downloaded from https://www.digicert.com/kb/digicert-root-certificates.htm
// 2. SmartHome Cluster CA - forgejo.intern and other *.intern services, valid until 2036-02-04
//    SHA-256 F2:F4:BE:60:5D:72:80:6F:0F:52:3F:F7:5A:51:08:0D:F2:26:B5:51:4E:3C:E2:0B:F0:42:B4:46:3B:0D:6D:3F

static const char *server_certificate = "-----BEGIN CERTIFICATE-----\n" \
"MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\n" \
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n" \
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n" \
"MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n" \
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n" \
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n" \
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\n" \
"2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\n" \
"1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\n" \
"q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\n" \
"tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\n" \
"vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\n" \
"BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\n" \
"5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\n" \
"1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\n" \
"NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\n" \
"Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\n" \
"8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\n" \
"pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\n" \
"MrY=\n" \
"-----END CERTIFICATE-----\n" \
"-----BEGIN CERTIFICATE-----\n" \
"MIIFCjCCAvKgAwIBAgIQWfzdRm19hW7Cq+dedQGhEjANBgkqhkiG9w0BAQsFADAf\n" \
"MR0wGwYDVQQDExRTbWFydEhvbWUgQ2x1c3RlciBDQTAeFw0yNjAyMDYxOTQyNTFa\n" \
"Fw0zNjAyMDQxOTQyNTFaMB8xHTAbBgNVBAMTFFNtYXJ0SG9tZSBDbHVzdGVyIENB\n" \
"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3qFf6n6Lo9a9XI4ETA+A\n" \
"YjoMJdtBhwXCDMTZwUZeIwoZJ4FaqE4YOoqYjc4fMHJo3GXOiQhaDtoRyGGDmClo\n" \
"B9FYq7IjdeQeJ/EijaFg9NgGrZDTupKDfFhPSzvMLntPToK1hE5xOO8VtCeL2M6A\n" \
"hhBRkMeL7+4dIxb8LbjBILjr0P62K8cS/hM/iVzpUdceFk9ktaASPwLE8JG/I/Zt\n" \
"tNtCu+4f9+7j+FTVNJTfLhxrCrPrDMecxMwu9qecbIFDXywDY4AESt/bWTxw+xNc\n" \
"VSfDXVLnTR1XgxyBy44UadRZloiCg0Ua2mTCtTVrr8YeIvNdetAp4M0Hnb9OhxOb\n" \
"uH1DCmGb49DF5311lwktQzc5GF+aSMO83OpGmpP4VkYGWkaHpEEdtyQjxf5gld/J\n" \
"cuXrXTi7JJj0Dp5ZwYtYJUHzeIuzI20IzyD5SJYmQP7397LVpEF5FxPJ+Te4cUKb\n" \
"NtRDwX0dx005SqdgsoSrKdyPyI/rVfmOF5pdJ4mGeW6b9rNMdJ1BpfFUOKoUeuIJ\n" \
"BHDyCmifM7zCaEMfITti8isWKOucMPKWtsSUhWWxNos+Dgd6TmsstUp6Cb8JBzt6\n" \
"tNaf/ogN3L4rYNlIJKhcsIGHn+zXXVoj9npZIlrtZkCoTV1AJShRA4U7eT3Z89NY\n" \
"GfpjM/B7nkudmib2z4VgC2cCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKkMA8GA1Ud\n" \
"EwEB/wQFMAMBAf8wHQYDVR0OBBYEFD0/MxteB1Mpv2/BNyh/En71Si6BMA0GCSqG\n" \
"SIb3DQEBCwUAA4ICAQBU5rNvXjgOxy6fwHcnQS45+5F+1bi4vcDsNF7CwryCZ/NE\n" \
"ateB7J6QXVE8QoHEdn6PINyOS7G0+ezJlE5TbyLMgmKn84ApbuDeGVFZfqfYnLyG\n" \
"MV2MFDWw5Pp9cdady/2z4WHtZCI4os58ikWjXavqQ83cpFLs2HGphLUGYE9yd6n9\n" \
"Qrhox2mAl0ZJMqDR2spcSqHsfUOIq8fpjWp9OnO5e+3Lbr6gE4K60+Ds8mjx10jN\n" \
"cMjMX/+lV+DmOM1dYJ0NEojj5Vs4yicrVCiyDQEPefVsB4EiHcFmh8ojA5+4AZdw\n" \
"gOQ14WTr9juDRnlKVSm3Pseugpeo3leLYcaHQceaLKFmGACY8P1v84byKwzzn3T0\n" \
"BU8Cu0XHxVo06jt7YUiz9ML1YhhErXUyDk9QJmFiAfj0UzTjTPp3R0jnDOgGT5vl\n" \
"GrGNmrH9iw0yN3fFY8kSqzHXbZuv8mSYyCJdFHS8HcqQEg1gvByPQINFtmDPZRik\n" \
"II04Yze0dwZkD2bsdYjmuGd3NXMIBZpHfzZAJVxcRKqhBSlFq4Qj0iiDmms3zsUK\n" \
"hk58cGE2W0E2E/XIYK9P7PK41ejoviK8jQCqdZZDcsye403HXA9cWqUbiCzcp3I4\n" \
"+VYAS8KqtkpUqikcEIXpt7wVMFHhVchnE0T8nQsEe9LXZ1TlDWWPselIr2L/yg==\n" \
"-----END CERTIFICATE-----";

void HttpEvent(HttpEvent_t *event)
{
    switch(event->event_id) {
        case HTTP_EVENT_ERROR:
            Serial.println("Http Event Error");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            Serial.println("Http Event On Connected");
            break;
        case HTTP_EVENT_HEADER_SENT:
            Serial.println("Http Event Header Sent");
            break;
        case HTTP_EVENT_ON_HEADER:
            Serial.printf("Http Event On Header, key=%s, value=%s\n", event->header_key, event->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            break;
        case HTTP_EVENT_ON_FINISH:
            Serial.println("Http Event On Finish");
            break;
        case HTTP_EVENT_DISCONNECTED:
            Serial.println("Http Event Disconnected");
            break;
        // case HTTP_EVENT_REDIRECT:
        //     Serial.println("Http Event Redirect");
        //     break;
    }
}

bool AzureOTAUpdater::UpdateFirmwareFromUrl(const char* firmwareUrl) {
    otaUrl = String(firmwareUrl);
    otaUrl.trim();

    Serial.print("Downloading new firmware from: ");
    Serial.println(otaUrl);
    
    HttpsOTA.onHttpEvent(HttpEvent);
    Serial.println("Starting OTA Update from Azure Blob Storage " + otaUrl + " ...");
    // false = check the host name. Only then does esp-tls send SNI; without SNI the cluster's
    // Traefik answers with its self-signed default certificate instead of the forgejo.intern one.
    HttpsOTA.begin(otaUrl.c_str(), server_certificate, false);
    Serial.println("OTA Update in progress...");
    return true;
}

int AzureOTAUpdater::CheckUpdateStatus()
{
    otastatus = HttpsOTA.status();
    if(otastatus == HTTPS_OTA_UPDATING) {
        Serial.println("OTA Update in progress...");
        return 1;
    } else if(otastatus == HTTPS_OTA_SUCCESS) { 
        Serial.println("Firmware written successfully. Rebooting now ...");
        ESP.restart();
        return 99;
    } else if(otastatus == HTTPS_OTA_FAIL) { 
        Serial.println("Firmware Upgrade Fail");
        return -1;
    }
    return 0;
}

String AzureOTAUpdater::ExtractVersionFromUrl(String url) {
    int lastUnderscoreIndex = url.lastIndexOf('_');
    int lastDotIndex = url.lastIndexOf('.');

    if (lastUnderscoreIndex != -1 && lastDotIndex != -1 && lastDotIndex > lastUnderscoreIndex) {
        return url.substring(lastUnderscoreIndex + 1, lastDotIndex);
    }

    return ""; // Return empty string if the pattern is not found
}