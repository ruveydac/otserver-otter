#include "iec61850_server.h"
#include "mms_value.h"
#include "hal_thread.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile int running = 1;

static void
stop_server(int signal_id)
{
    (void) signal_id;
    running = 0;
}

static void
set_string(ModelNode* parent, const char* name, const char* value)
{
    DataAttribute* attribute = (DataAttribute*) ModelNode_getChild(parent, name);

    if (attribute != NULL)
        DataAttribute_setValue(attribute, MmsValue_newVisibleString(value));
}

static void
set_boolean(ModelNode* parent, const char* name, bool value)
{
    DataAttribute* attribute = (DataAttribute*) ModelNode_getChild(parent, name);

    if (attribute != NULL)
        DataAttribute_setValue(attribute, MmsValue_newBoolean(value));
}

static void
set_integer(ModelNode* parent, const char* name, int32_t value)
{
    DataAttribute* attribute = (DataAttribute*) ModelNode_getChild(parent, name);

    if (attribute != NULL)
        DataAttribute_setValue(attribute, MmsValue_newIntegerFromInt32(value));
}

static void
set_double_point(ModelNode* parent, const char* name, uint32_t value)
{
    DataAttribute* attribute = (DataAttribute*) ModelNode_getChild(parent, name);

    if (attribute != NULL) {
        MmsValue* position = MmsValue_newBitString(2);
        MmsValue_setBitStringFromInteger(position, value);
        DataAttribute_setValue(attribute, position);
    }
}

int
main(int argc, char** argv)
{
    int tcp_port = 102;
    if (argc > 1)
        tcp_port = atoi(argv[1]);

    IedModel* model = IedModel_create("OTTERIED");
    IedModel_setIedNameForDynamicModel(model, "OTTERIED");

    LogicalDevice* device = LogicalDevice_create("LD0", model);

    LogicalNode* lln0 = LogicalNode_create("LLN0", device);
    DataObject* name_plate = CDC_LPL_create("NamPlt", (ModelNode*) lln0, 0);
    DataObject* lln0_health = CDC_ENS_create("Health", (ModelNode*) lln0, 0);
    CDC_ENS_create("Beh", (ModelNode*) lln0, 0);

    LogicalNode* lphd1 = LogicalNode_create("LPHD1", device);
    DataObject* physical_name = CDC_DPL_create(
        "PhyNam",
        (ModelNode*) lphd1,
        CDC_OPTION_DPL_HWREV
            | CDC_OPTION_DPL_SWREV
            | CDC_OPTION_DPL_SERNUM
            | CDC_OPTION_DPL_MODEL
            | CDC_OPTION_DPL_LOCATION);
    DataObject* physical_health = CDC_SPS_create("PhyHealth", (ModelNode*) lphd1, 0);

    LogicalNode* xcbr1 = LogicalNode_create("XCBR1", device);
    DataObject* position = CDC_DPC_create("Pos", (ModelNode*) xcbr1, 0, CDC_CTL_MODEL_NONE);
    DataObject* block_open = CDC_SPS_create("BlkOpn", (ModelNode*) xcbr1, 0);
    DataObject* block_close = CDC_SPS_create("BlkCls", (ModelNode*) xcbr1, 0);
    DataObject* operation_count = CDC_INS_create("OpCnt", (ModelNode*) xcbr1, 0);

    set_string((ModelNode*) name_plate, "vendor", "OT Lab Automation");
    set_string((ModelNode*) name_plate, "model", "libIEC61850 Test IED");
    set_string((ModelNode*) name_plate, "serNum", "IEDLAB0001");
    set_string((ModelNode*) name_plate, "swRev", "1.6.2");
    set_string((ModelNode*) name_plate, "location", "OT Lab / Substation 1");

    set_string((ModelNode*) physical_name, "vendor", "OT Lab Automation");
    set_string((ModelNode*) physical_name, "model", "IEC 61850 Breaker IED");
    set_string((ModelNode*) physical_name, "serNum", "IEDLAB0001");
    set_string((ModelNode*) physical_name, "hwRev", "HW-2");
    set_string((ModelNode*) physical_name, "swRev", "1.6.2");
    set_string((ModelNode*) physical_name, "location", "OT Lab / Substation 1");

    set_integer((ModelNode*) lln0_health, "stVal", 1);
    set_boolean((ModelNode*) physical_health, "stVal", true);
    set_double_point((ModelNode*) position, "stVal", 2);
    set_boolean((ModelNode*) block_open, "stVal", false);
    set_boolean((ModelNode*) block_close, "stVal", false);
    set_integer((ModelNode*) operation_count, "stVal", 42);

    IedServerConfig config = IedServerConfig_create();
    IedServerConfig_enableFileService(config, false);
    IedServerConfig_enableDynamicDataSetService(config, false);
    IedServerConfig_enableLogService(config, false);
    IedServerConfig_enableEditSG(config, false);
    IedServerConfig_setMaxMmsConnections(config, 2);

    IedServer server = IedServer_createWithConfig(model, NULL, config);
    IedServerConfig_destroy(config);
    IedServer_setWriteAccessPolicy(server, IEC61850_FC_ALL, ACCESS_POLICY_DENY);
    IedServer_setServerIdentity(server, "OT Lab Automation", "libIEC61850 Test IED", "1.6.2");
    IedServer_start(server, tcp_port);

    if (!IedServer_isRunning(server)) {
        fprintf(stderr, "could not start libIEC61850 server on TCP port %d\n", tcp_port);
        IedServer_destroy(server);
        IedModel_destroy(model);
        return EXIT_FAILURE;
    }

    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    while (running)
        Thread_sleep(1000);

    IedServer_stop(server);
    IedServer_destroy(server);
    IedModel_destroy(model);
    return EXIT_SUCCESS;
}
