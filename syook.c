#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/sket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define OLC 0x08
#define ENABLE 0x000C

int id = -1;
int sk;

void signal_init(int signal) {
    hci_set(sk, 0x00, 1, 1000);
    close(sk);
    exit(0);
}

int main() {
    signal(SIGINT, signal_init);

    id = hci_get(NULL);
    if (id < 0) {
        perror("Could not get HCI device ID");
        exit(1);
    }

    sk = open_dev(id);
    if (sk < 0) {
        perror("Could not open HCI sket");
        exit(1);
    }

    le_set_scan_parameters(sk);
    le_enable_scan(sk);

    while (1) {
        struct hci_filter old_op;
        sklen_t olen = sizeof(old_op);
        struct hci_filter new_op;
        sklen_t nlen = sizeof(new_op);

        getskopt(sk, SOL_HCI, HCI_FILTER, &old_op, &olen);

        hci_filter_clear(&new_op);
        hci_filter_set_ptype(HCI_EVENT_PKT, &new_op);
        hci_filter_set_event(EVT_LE_META_EVENT, &new_op);
        setskopt(sk, SOL_HCI, HCI_FILTER, &new_op, sizeof(new_op));

        uint8_t buf[HCI_MAX_EVENT_SIZE];
        ssize_t len = read(sk, buf, sizeof(buf));

        hci_filter_clear(&new_op);
        hci_filter_set_ptype(HCI_EVENT_PKT, &new_op);
        hci_filter_set_event(EVT_LE_META_EVENT, &new_op);
        setskopt(sk, SOL_HCI, HCI_FILTER, &new_op, sizeof(new_op));

        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + (1 + HCI_EVENT_HDR_SIZE));
        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);

        if (meta->subevent != 0x02) {
            continue;
        }

        // Extract accelerometer data from the advertising payload
        uint8_t *adv_data = info->data;
        while (adv_data < (info->data + info->length)) {
            uint8_t len = adv_data[0];
            uint8_t type = adv_data[1];

            if (type == 0xFF) {  // Manufacturer Specific Data
                if (len >= 7 && adv_data[2] == 0x4C && adv_data[3] == 0x00) {
                    int16_t x = (adv_data[4] << 8) | adv_data[5];
                    int16_t y = (adv_data[6] << 8) | adv_data[7];
                    int16_t z = (adv_data[8] << 8) | adv_data[9];

                    // TODO: Add logic to determine if the tag is moving or stationary based on accelerometer data
                    if (x + y + z > MOVEMENT_THRESHOLD) {
                        printf("Tag is moving\n");
                    } else {
                        printf("Tag is stationary\n");
                    }
                }
            }

            adv_data += (len + 1);
        }
    }

    hci_set(sk, 0x00, 1, 1000);
    close(sk);

    return 0;
}
