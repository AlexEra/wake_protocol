#ifndef WAKE_BASE_PROTOCOL_H
#define WAKE_BASE_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>


#define WAKE_MAX_PACKAGE_LEN 520

typedef enum {
	FEND  = 0xC0, // 192
	FESC  = 0xDB, // 219
	TFEND = 0xDC, // 220
	TFESC = 0xDD  // 221
} service_bytes_t;

typedef struct {
	uint8_t start_byte;
	uint8_t addr;
	uint8_t cmd;
	uint8_t n;
	uint8_t data[255];
	uint8_t crc;
} wake_package_info_t;

typedef enum {
	WAKE_OK,
	WAKE_ADDR_ERROR,
	WAKE_CMD_ERROR,
	WAKE_BUF_LEN_ERROR,
	WAKE_READY_ERROR
} wake_status_t;


// Macroses for creating the message structure with some parameters
#define WAKE_PKG_STRUCT(struct_name, a, c, n_len) wake_package_info_t struct_name = {\
		.addr = a,\
		.cmd = c,\
		.n = n_len\
}

#define WAKE_PKG_STRUCT_REDUCED(struct_name, c, n_len) wake_package_info_t struct_name = {\
		.cmd = c,\
		.n = n_len\
}


/**
 * @brief Unstuffing the input byte
 * 
 * If there is mathcing with FEND or FESC, 1 will be returned, 0 otherwise.
 * This flag helps to control ubnstuffing process to fill the array with correct bytes.
 * Outer process should check this flag and write to array the next value, if returned
 * flag is 1. If this flag is 0, input byte can be written to the array  
 * 
 * @param byte[out]       Byte for processing
 * @param unstuffing_flag Flag to control unstuffing process
 * 
 * @return Flag that should be used in cycle as unstuffing_flag 
 */
uint8_t wake_unstuffing(uint8_t *byte, uint8_t unstuffing_flag);

/**
 * @brief Stuffing the byte if it matches with FEND or FESC
 *
 * Allows to replace matching bytes. If there is need for stuffing, 1 will be returned and
 * stuff_byte should be used for transmission with changed n_byte
 * In 0 case there is no need to transmit stuff_byte, it is enough to send only in_byte
 * 
 * @param in_byte[out]    Pointer to the source byte
 * @param stuff_byte[out] Pointer to the byte for stuffing case
 * 
 * @return Bool stuffing status (1/0)
 */
uint8_t wake_stuffing(uint8_t *in_byte, uint8_t *stuff_byte);

/**
 * @brief Calculation of the CRC8
 * 
 * @param buf Buffer for checking the CRC8
 * @param len Buffer length in bytes
 * 
 * @return Calculated CRC8 value
 */
uint8_t wake_calculate_crc(uint8_t *buf, size_t len);

/**
 * @brief Calculation of the CRC8 for Wake package format
 * 
 * @param p_package   Pointer to the package
 * @param package_len Lenght of the input package in bytes
 * @param ignoring_address_flag Flag, meaning that address filed is ignored in transmittion process
 * 
 * @return Calculated CRC8 value
 */
uint8_t wake_calculate_package_crc(wake_package_info_t *p_package, uint8_t ignoring_address_flag);

/**
 * @brief Check the CRC8 result with given data
 * 
 * If there is critical data errors, 0 will be returned.
 * Otherwise 1.
 * Function should be used after forming the resulting package, i.e. after unstuffing process
 * 
 * @param p_package   Pointer to the data package
 * @param ignoring_address_flag Flag, meaning that address filed is ignored in transmittion process
 * 
 * @return Bool checking status (1/0)
 */
uint8_t wake_check_crc(wake_package_info_t *p_package, uint8_t ignoring_address_flag);

/**
 * @brief Transform Wake package to the bytes
 * 
 * To detect buf_len the wake_total_bytes_count function should be called. The returned value is buf_len
 * 
 * @param  p_package[in] Pointer to the package
 * @param ignoring_address_flag[in] Flag, meaning that address filed is ignored in transmittion process
 * @param  buf[out]      Pointer to the output bytes
 * @param  p_size[out]   Pointer for keeping the length of the bytes buffer
 * 
 * @return Execution status
 */
wake_status_t wake_package_to_bytes(wake_package_info_t *p_package, uint8_t ignoring_address_flag, uint8_t *buf, uint16_t *p_size);

/**
 * @brief Transform bytes to the Wake package format
 * 
 * @param buf[in]       Pointer to the bytes
 * @param buf_len[in]   Total length of the bytes buffer
 * @param ignoring_address_flag[in] Flag, meaning that address filed is ignored in transmittion process
 * @param p_package[out] Pointer to the package (bytes will be written there)
 * 
 * @return Execution status
 */
wake_status_t wake_bytes_to_package(uint8_t *buf, size_t buf_len, uint8_t ignoring_address_flag, wake_package_info_t *p_package);

#endif
