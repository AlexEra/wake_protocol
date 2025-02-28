#include "wake_base_protocol.h"


/// Table for CRC8 poly calculations
const uint8_t crc_table[] = {
	0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
	157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
	35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
	190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
	70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
	219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
	101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
	248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
	140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
	17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
	175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
	50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
	202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
	87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
	233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
	116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
};

/**
 * @brief Detect stuffed byte
 * 
 * @param bt Input byte
 * 
 * @return FEND or FESC if byte was stuffed, otherwise byte won't be changed
 */
static uint8_t process_byte(uint8_t bt) {
	switch (bt) {
		case TFEND: return FEND;
		case TFESC: return FESC;
		default: return bt;
	}
}

/**
 * @brief Checking the stuffing necessity
 * 
 * @param value Input byte
 * 
 * @return 2 in case of stuffing, 1 otherwise
 */
static inline uint8_t check_stuffing_case(uint8_t value) {
	return ((value == FEND) || (value == FESC)) ? 2 : 1;
}

uint8_t wake_unstuffing(uint8_t *byte, uint8_t unstuffing_flag) {
	if (*byte == FESC) {
		return 1;
	} else if (unstuffing_flag) {
		*byte = process_byte(*byte);
		return 0;
	} else {
		return 0;
	}
}

uint8_t wake_stuffing(uint8_t *in_byte, uint8_t *stuff_byte) {
	switch (*in_byte) {
		case FEND:
			*in_byte = FESC;
			*stuff_byte = TFEND;
			return 1;
		case FESC:
			*in_byte = FESC;
			*stuff_byte = TFESC;
			return 1;
		default: return 0;
	}
}

uint8_t wake_calculate_crc(uint8_t *buf, size_t len) {
	uint8_t crc = 0xDE;
	for (size_t i = 0; i < len; i++) crc = crc_table[crc ^ *(buf++)];
	return crc;
}

uint8_t wake_calculate_package_crc(wake_package_info_t *p_package, uint8_t ignoring_address_flag) {
	if (ignoring_address_flag) {
		p_package->addr = FEND;
		return wake_calculate_crc(&p_package->addr, p_package->n + 3);
	} else {
		p_package->start_byte = FEND;
		return wake_calculate_crc((uint8_t *) p_package, p_package->n + 4);
	}
}

uint8_t wake_check_crc(wake_package_info_t *p_package, uint8_t ignoring_address_flag) {
	uint8_t res_crc	= wake_calculate_package_crc(p_package, ignoring_address_flag);
	return res_crc == p_package->crc;
}

wake_status_t wake_package_to_bytes(wake_package_info_t *p_package, uint8_t ignoring_address_flag, uint8_t *buf, uint16_t *p_size) {
	uint8_t extending_byte;
	size_t idx = 0;
	uint8_t flag = 0;
	uint8_t *p_pckg = (uint8_t *) p_package;
	size_t buf_len;

	/// defining the max buffer length (w/o stuffed bytes)
	if (ignoring_address_flag) {
		buf_len = p_package->n + 4;
	} else {
		buf_len = p_package->n + 5;
	}

	/// protocol checking
	if (!ignoring_address_flag && p_package->addr > 0x80) return WAKE_ADDR_ERROR;
	if (p_package->cmd > 0x7F) return WAKE_CMD_ERROR;

	/// forming the start byte
	p_package->start_byte = FEND;

	/// forming the address
	p_package->addr |= 0x80;

	*p_size = 1; // including the start byte

	/// fill the buffer
	buf[idx++] = *p_pckg++; // saving the start_byte, because it can't be replaced
	if (ignoring_address_flag) p_pckg++; // incrementing pointer for ignoring address byte

	while (idx < buf_len) {
		flag = wake_stuffing(p_pckg, &extending_byte);
		if (flag) {
			/// stuffing case
			buf[idx++] = *p_pckg;
			buf[idx] = extending_byte;
			*p_size += 2;
			buf_len++;
		} else {
			/// set the clear byte without stuffing
			(*p_size)++;
			buf[idx] = *p_pckg;
		}
		idx++;
		if (++p_pckg == &p_package->data[p_package->n]) p_pckg = &p_package->crc;
	}
	// revert address value
	p_package->addr &= 0x7F;

	return WAKE_OK;
}

wake_status_t wake_bytes_to_package(uint8_t *buf, size_t buf_len, uint8_t ignoring_address_flag, wake_package_info_t *p_package) {
	uint8_t reduce_len_flag = 0;
	uint8_t *p_pckg = (uint8_t *) p_package;

	if (buf_len > 264) return WAKE_BUF_LEN_ERROR;

	p_package->start_byte = FEND;
	p_pckg++;
	if (ignoring_address_flag) p_pckg++;

	/// starting with next byte after start byte (from addr or cmd, depends on ignoring_address_flag)
	for (size_t i = 1; i < buf_len; i++) {
		if (i == (buf_len - 1)) {
			p_package->crc = buf[i]; /// adding the crc value to the corresponding package field
			p_pckg = &p_package->crc;
		} else {
			*p_pckg = buf[i];    
		}

		reduce_len_flag = wake_unstuffing(p_pckg, reduce_len_flag);
		if (!reduce_len_flag) p_pckg++;
	}

	if (!ignoring_address_flag && p_package->addr < 0x80) return WAKE_ADDR_ERROR;
	if (p_package->cmd > 0x7F) return WAKE_CMD_ERROR;

	p_package->addr &= 0x7F; // excluding the 0x80 bit   

	return WAKE_OK;
}
