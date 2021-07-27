#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <iotp_device.h>

volatile sig_atomic_t deamonize = 1;

enum {
	TOTAL_MEMORY,
	FREE_MEMORY,
	SHARED_MEMORY,
	BUFFERED_MEMORY,
	__MEMORY_MAX,
};

enum {
	MEMORY_DATA,
	__INFO_MAX,
};

struct memdata {
    long int total;
    long int freed;
    long int buffered;
    long int shared;
};

struct config
{
    char orgid[256];
    char typeid[256];
    char deviceid[256];
    char token[256];
};

const struct blobmsg_policy memory_policy[__MEMORY_MAX] = {
	[TOTAL_MEMORY] = { .name = "total", .type = BLOBMSG_TYPE_INT64 },
	[FREE_MEMORY] = { .name = "free", .type = BLOBMSG_TYPE_INT64 },
	[SHARED_MEMORY] = { .name = "shared", .type = BLOBMSG_TYPE_INT64 },
	[BUFFERED_MEMORY] = { .name = "buffered", .type = BLOBMSG_TYPE_INT64 },
};

const struct blobmsg_policy info_policy[__INFO_MAX] = {
	[MEMORY_DATA] = { .name = "memory", .type = BLOBMSG_TYPE_TABLE },
};

int sig_handler();

int getConfigProperty(char *path, char *string);

int getConfig(struct config *conf);

void board_cb(struct ubus_request *req, int type, struct blob_attr *msg);

int connectWatson(IoTPDevice **device, IoTPConfig **config);

int main(void)
{
    struct memdata memoryData = {0};
    struct config conf = {0};
    IoTPConfig *config = NULL;
    IoTPDevice *device = NULL;
    int rc = 0;
    char jsonString[256];

    fprintf(stdout,"[INFO] Starting daemon\n");
    signal(SIGINT, sig_handler);

    rc = connectWatson(&device, &config);
    if(rc != IOTPRC_SUCCESS){
        rc = -1;
        fprintf(stderr, "[ERROR] Couldn't connect to IoT Watson platform. Exiting daemon\n");
        return rc;
    }
    fprintf(stdout, "[INFO] Successfully connected to IoT Watson platform\n");

    while(deamonize){
        time_t current_time = time(NULL);
        char *c_time_string = ctime(&current_time);
        c_time_string[strlen(c_time_string)-1] = 0;
        struct ubus_context *ctx;
        uint32_t id;
        ctx = ubus_connect(NULL);
        if (!ctx) {
            fprintf(stderr, "[ERROR] Failed to connect to ubus\n");
            rc = -1;
            goto cleanup;
        }
        if (ubus_lookup_id(ctx, "system", &id) || ubus_invoke(ctx, id, "info", NULL, board_cb, &memoryData, 3000)) {
                fprintf(stderr, "[ERROR]cannot request memory info from procd\n");
                rc=-1;
                ubus_free(ctx);
                goto cleanup;
        }
        fprintf(stdout, "[INFO] Successfully found memory info\n");
        
        snprintf(jsonString, sizeof(jsonString), "{ \"Memory\" : { \"Total memory\" : %ld, \"Free memory\" : %ld, \"Shared memory\" : %ld, \"Buffered memory\" : %ld   }}", memoryData.total, memoryData.freed, memoryData.shared, memoryData.buffered);
        IoTPDevice_sendEvent(device,"Memory status", jsonString, "json", QoS0, NULL);
        if ( rc != IOTPRC_SUCCESS ) {
            fprintf(stderr,"[ERROR] Failed to publish event");
        }
        fprintf(stdout, "[INFO] Successfully published memory info\n");
        ubus_free(ctx);
        sleep(1);
    }
    cleanup:
        fprintf(stdout, "[INFO] Exiting daemon\n");       
        IoTPDevice_disconnect(device);
        IoTPDevice_destroy(device);
        IoTPConfig_clear(config);
    return rc;
}

int sig_handler()
{
    deamonize = 0;
}

int getConfigProperty(char *path, char *string)
{
    int rc = 0;
    struct uci_context *c;
    struct uci_ptr ptr;

    c = uci_alloc_context ();
    if (uci_lookup_ptr (c, &ptr, path, false) != UCI_OK)
    {
        uci_perror (c, "get_config_entry Error");
        rc = -1;
        return rc;
    }
    strcpy(string, ptr.o->v.string);
    uci_free_context(c);
    return rc;
}

int getConfig(struct config *conf)
{
    int rc = 0;
    char orgPath[] = "watson.watson_sct.org_id";
    char typePath[] = "watson.watson_sct.type_id";
    char devicePath[] = "watson.watson_sct.device_id";
    char tokenPath[] = "watson.watson_sct.token";

    getConfigProperty(orgPath, conf->orgid);
    getConfigProperty(typePath, conf->typeid);
    getConfigProperty(devicePath, conf->deviceid);
    getConfigProperty(tokenPath, conf->token);
    return rc; 
}

void board_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	
	struct blob_attr *tb[__INFO_MAX];
	struct blob_attr *memory[__MEMORY_MAX];
    struct memdata *data = (struct memdata *)req->priv;
	blobmsg_parse(info_policy, __INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[MEMORY_DATA]) {
		fprintf(stderr, "No memory data received\n");
		return;
	}
	blobmsg_parse(memory_policy, __MEMORY_MAX, memory, blobmsg_data(tb[MEMORY_DATA]), blobmsg_data_len(tb[MEMORY_DATA]));
    data->total = blobmsg_get_u64(memory[TOTAL_MEMORY]);
    data->freed = blobmsg_get_u64(memory[FREE_MEMORY]);
    data->shared = blobmsg_get_u64(memory[SHARED_MEMORY]);
    data->buffered = blobmsg_get_u64(memory[BUFFERED_MEMORY]);
}

int connectWatson(IoTPDevice **device, IoTPConfig **config)
{
    struct config conf = {0};
    int rc = 0;

    rc = getConfig(&conf);
    if(rc != 0){
        return rc;
    }
    rc = IoTPConfig_create(config, NULL);
    if ( rc != 0 ) {
        fprintf(stderr, "[ERROR] Failed to configure IoTP device: rc=%d\n", rc);
        rc = 2;
        return rc;
    }

    IoTPConfig_setProperty(*config, "identity.orgId", conf.orgid);
    IoTPConfig_setProperty(*config, "identity.typeId", conf.typeid);
    IoTPConfig_setProperty(*config, "identity.deviceId", conf.deviceid);
    IoTPConfig_setProperty(*config, "auth.token", conf.token);

    if ( rc != IOTPRC_SUCCESS ) {
        rc =-1;
        return rc;
    }
    if (IoTPDevice_create(device,*config) != IOTPRC_SUCCESS ){
        fprintf(stderr, "[ERROR] Failed to create device client: rc=%d reason=%s\n", rc, IOTPRC_toString(rc));
        rc =-1;
        return rc;
    }

    if (IoTPDevice_connect(*device) != IOTPRC_SUCCESS ){
        fprintf(stderr, "[ERROR] Failed to connect to device client: rc=%d reason=%s\n", rc, IOTPRC_toString(rc));
        rc =-1;
        return rc;
    }
    return rc;
}
