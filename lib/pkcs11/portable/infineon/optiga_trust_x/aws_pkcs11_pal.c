/*
 * Amazon FreeRTOS PKCS #11 PAL for Infineon XMC4800 IoT Connectivity Kit V1.0.1
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Copyright (c) 2018, Infineon Technologies AG
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,are permitted provided that the
 * following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the copyright holders nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE  FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * To improve the quality of the software, users are encouraged to share modifications, enhancements or bug fixes with
 * Infineon Technologies AG dave@infineon.com).
 */


/**
 * @file aws_pkcs11_pal.c
 * @brief Amazon FreeRTOS device specific helper functions for
 * PKCS#11 implementation based on mbedTLS.  This
 * file deviates from the FreeRTOS style standard for some function names and
 * data types in order to maintain compliance with the PKCS#11 standard.
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "task.h"
#include "semphr.h"

#include "aws_crypto.h"
#include "aws_pkcs11.h"
#include "aws_pkcs11_config.h"

/* C runtime includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "optiga/optiga_util.h"
#include "optiga/comms/optiga_comms.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

#define pkcs11OBJECT_CERTIFICATE_MAX_SIZE    2048

#define pkcs11OBJECT_FLASH_OBJECT_PRESENT    ( 0xABCDEFuL )

enum eObjectHandles
{
    eInvalidHandle = 0, /* According to PKCS #11 spec, 0 is never a valid object handle. */
    eAwsDevicePrivateKey = 1,
    eAwsDevicePublicKey,
    eAwsDeviceCertificate,
    eAwsCodeSigningKey
};


optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_0,NULL,NULL, OPTIGA_COMMS_SUCCESS};

/*-----------------------------------------------------------*/

/**
 * @brief Saves an object in non-volatile storage.
 *
 * Port-specific file write for cryptographic information.
 *
 * @param[in] pxLabel       The label of the object to be stored.
 * @param[in] pucData       The object data to be saved
 * @param[in] pulDataSize   Size (in bytes) of object data.
 *
 * @return The object handle if successful.
 * eInvalidHandle = 0 if unsuccessful.
 */
CK_OBJECT_HANDLE PKCS11_PAL_SaveObject( CK_ATTRIBUTE_PTR pxLabel,
                                        uint8_t * pucData,
                                        uint32_t ulDataSize )
{
    CK_OBJECT_HANDLE xHandle = eInvalidHandle;

    long     lOptigaOid = 0;
    uint8_t  bOffset = 0;
    char*    xEnd = NULL;

    optiga_lib_status_t xReturn;


    if( ulDataSize <= pkcs11OBJECT_CERTIFICATE_MAX_SIZE )
    {
        /* Translate from the PKCS#11 label to local storage file name. */
        if( 0 == memcmp( pxLabel->pValue,
                         &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                         sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
        {
            /**
             * Write a certificate to a given cert object (e.g. E0E8)
             * using optiga_util_write_data.
             *
             * Use Erase and Write (OPTIGA_UTIL_ERASE_AND_WRITE) option,
             * to clear the remaining data in the object
             */

        	lOptigaOid = strtol(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, &xEnd, 16);

        	if ( (0 != lOptigaOid) && (USHRT_MAX > lOptigaOid) && (USHRT_MAX > ulDataSize))
        	{
				xReturn = optiga_util_write_data((uint16_t)lOptigaOid,
												 OPTIGA_UTIL_ERASE_AND_WRITE,
												 bOffset,
												 pucData,
												 ulDataSize);
				if (OPTIGA_LIB_SUCCESS == xReturn)
					xHandle = eAwsDeviceCertificate;
        	}
        }
        else if( 0 == memcmp( pxLabel->pValue,
                              &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) )
        {
            /* This operation isn't supported for the OPTIGA(TM) Trust X due to a security considerations
             * You can only generate a keypair and export a private component if you like */
        	/* We do assign a handle though, as the AWS can#t handle the lables without having a handle*/
        	xHandle = eAwsDevicePrivateKey;
        }
        else if( 0 == memcmp( pxLabel->pValue,
                              &pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) ) )
        {
            /**
             * Write a public key to an arbitrary data object
             * Note: You might need to lock the data object here. see optiga_util_write_metadata()
             *
             * Use Erase and Write (OPTIGA_UTIL_ERASE_AND_WRITE) option,
             * to clear the remaining data in the object
             */
        	lOptigaOid = strtol(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, &xEnd, 16);

        	if ( (0 != lOptigaOid) && (USHRT_MAX >= lOptigaOid) && (USHRT_MAX >= ulDataSize))
        	{
				xReturn = optiga_util_write_data((uint16_t)lOptigaOid,
												 OPTIGA_UTIL_ERASE_AND_WRITE,
												 bOffset,
												 pucData,
												 ulDataSize);
				if (OPTIGA_LIB_SUCCESS == xReturn)
					xHandle = eAwsDevicePublicKey;
        	}
        }
        else if( 0 == memcmp( pxLabel->pValue,
                              &pkcs11configLABEL_CODE_VERIFICATION_KEY,
                              sizeof( pkcs11configLABEL_CODE_VERIFICATION_KEY ) ) )
        {
            /**
             * Write a Code Verification Key/Certificate to an Trust Anchor data object
             * Note: You might need to lock the data object here. see optiga_util_write_metadata()
             *
             * Use Erase and Write (OPTIGA_UTIL_ERASE_AND_WRITE) option,
             * to clear the remaining data in the object
             */
        	lOptigaOid = strtol(pkcs11configLABEL_CODE_VERIFICATION_KEY, &xEnd, 16);

        	if ( (0 != lOptigaOid) && (USHRT_MAX > lOptigaOid) && (USHRT_MAX > ulDataSize))
        	{
				xReturn = optiga_util_write_data((uint16_t)lOptigaOid,
												 OPTIGA_UTIL_ERASE_AND_WRITE,
												 bOffset,
												 pucData,
												 ulDataSize);

				if (OPTIGA_LIB_SUCCESS == xReturn)
					xHandle = eAwsCodeSigningKey;
        	}
        }

    }

    return xHandle;
}


/*-----------------------------------------------------------*/

/**
 * @brief Translates a PKCS #11 label into an object handle.
 *
 * Port-specific object handle retrieval.
 *
 *
 * @param[in] pxLabel         Pointer to the label of the object
 *                           who's handle should be found.
 * @param[in] usLength       The length of the label, in bytes.
 *
 * @return The object handle if operation was successful.
 * Returns eInvalidHandle if unsuccessful.
 */
CK_OBJECT_HANDLE PKCS11_PAL_FindObject( uint8_t * pLabel,
                                        uint8_t usLength )
{
    CK_OBJECT_HANDLE xHandle = eInvalidHandle;

    /* Translate from the PKCS#11 label to local storage file name. */
    if( 0 == memcmp( pLabel,
                     &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                     sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
    {
        xHandle = eAwsDeviceCertificate;
    }
    else if( 0 == memcmp( pLabel,
                          &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                          sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) )
    {
        /* This operation isn't supported for the OPTIGA(TM) Trust X due to a security considerations
         * You can only generate a keypair and export a private component if you like */
    	/* We do assign a handle though, as the AWS can#t handle the lables without having a handle*/
    	xHandle = eAwsDevicePrivateKey;
    }
    else if( 0 == memcmp( pLabel,
                          &pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                          sizeof( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) ) )
    {
        xHandle = eAwsDevicePublicKey;
    }
    else if( 0 == memcmp( pLabel,
                          &pkcs11configLABEL_CODE_VERIFICATION_KEY,
                          sizeof( pkcs11configLABEL_CODE_VERIFICATION_KEY ) ) )
    {
        xHandle = eAwsCodeSigningKey;
    }

    return xHandle;
}

/*-----------------------------------------------------------*/

/**
 * @brief Gets the value of an object in storage, by handle.
 *
 * Port-specific file access for cryptographic information.
 *
 * This call dynamically allocates the buffer which object value
 * data is copied into.  PKCS11_PAL_GetObjectValueCleanup()
 * should be called after each use to free the dynamically allocated
 * buffer.
 *
 * @sa PKCS11_PAL_GetObjectValueCleanup
 *
 * @param[in] pcFileName    The name of the file to be read.
 * @param[out] ppucData     Pointer to buffer for file data.
 * @param[out] pulDataSize  Size (in bytes) of data located in file.
 * @param[out] pIsPrivate   Boolean indicating if value is private (CK_TRUE)
 *                          or exportable (CK_FALSE)
 *
 * @return CKR_OK if operation was successful.  CKR_KEY_HANDLE_INVALID if
 * no such object handle was found, CKR_DEVICE_MEMORY if memory for
 * buffer could not be allocated, CKR_FUNCTION_FAILED for device driver
 * error.
 */
CK_RV PKCS11_PAL_GetObjectValue( CK_OBJECT_HANDLE xHandle,
                                 uint8_t ** ppucData,
                                 uint32_t * pulDataSize,
                                 CK_BBOOL * pIsPrivate )
{
	CK_RV                ulReturn = CKR_OK;
    optiga_lib_status_t  xReturn;
    long                 lOptigaOid = 0;
    char*                xEnd = NULL;
    uint8_t              xOffset = 0;

    *pIsPrivate = CK_FALSE;

    *ppucData = pvPortMalloc( 1200 );
    *pulDataSize = 1200;


    switch (xHandle) {
    case eAwsDeviceCertificate:
    	lOptigaOid = strtol(pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, &xEnd, 16);
    	break;
    case eAwsDevicePublicKey:
    	lOptigaOid = strtol(pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, &xEnd, 16);
    	break;
    case eAwsCodeSigningKey:
    	lOptigaOid = strtol(pkcs11configLABEL_CODE_VERIFICATION_KEY, &xEnd, 16);
    	break;
    case eAwsDevicePrivateKey:
    	/*
    	 * This operation isn't supported for the OPTIGA(TM) Trust X due to a security considerations
    	 * You can only generate a keypair and export a private component if you like
    	 */
    default:
    	ulReturn = CKR_KEY_HANDLE_INVALID;
    	break;
    }

    if ( (0 != lOptigaOid) && (USHRT_MAX > lOptigaOid) &&
         (NULL != *ppucData) && (NULL != pulDataSize))
    {

        xReturn = optiga_util_read_data(lOptigaOid, xOffset, *ppucData, pulDataSize);

	    if (OPTIGA_LIB_SUCCESS != xReturn)
	    {
	    	*ppucData = NULL;
	    	*pulDataSize = 0;
	    	ulReturn = CKR_KEY_HANDLE_INVALID;
	    }
    }

    return ulReturn;
}

/*-----------------------------------------------------------*/

/**
 * @brief Cleanup after PKCS11_GetObjectValue().
 *
 * @param[in] pucData       The buffer to free.
 *                          (*ppucData from PKCS11_PAL_GetObjectValue())
 * @param[in] ulDataSize    The length of the buffer to free.
 *                          (*pulDataSize from PKCS11_PAL_GetObjectValue())
 */
void PKCS11_PAL_GetObjectValueCleanup( uint8_t * pucData,
                                       uint32_t ulDataSize )
{
    /* Unused parameters. */
    ( void ) pucData;
    ( void ) ulDataSize;

    vPortFree( pucData );

    /* Since no buffer was allocated on heap, there is no cleanup
     * to be done. */
}
/*-----------------------------------------------------------*/
