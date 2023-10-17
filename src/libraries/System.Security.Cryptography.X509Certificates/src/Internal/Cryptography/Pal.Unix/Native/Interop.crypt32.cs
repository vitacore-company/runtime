// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Text;
using System.Runtime.InteropServices;

using Internal.Cryptography.Pal.Native;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.CodeAnalysis;

internal static partial class Interop
{
    public static partial class Crypt32
    {
        internal const string ADVAPI32 = "libcapi20";
        internal const string CRYPT32 = "libcapi20";

        // Copied from win32
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptMsgClose(IntPtr hCryptMsg);

        // Copied from win32
        [DllImport(CRYPT32)]
        public static extern void CertFreeCertificateChainEngine(IntPtr hChainEngine);

        // Copied from win32
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeCertStoreHandle PFXImportCertStore([In] CRYPTOAPI_BLOB pPFX, [In] SafePasswordHandle szPassword, [In] PfxCertStoreFlags dwFlags);

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool PFXVerifyPassword([In] CRYPTOAPI_BLOB pPFX, [In][MarshalAs(UnmanagedType.LPWStr)] string szPassword, [In] uint dwFlags);

        // Copied from win32
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern unsafe bool CryptMsgGetParam(SafeCryptMsgHandle hCryptMsg, CryptMessageParameterType dwParamType, int dwIndex, byte* pvData, [In, Out] ref int pcbData);

        // Copied from win32
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptMsgGetParam(SafeCryptMsgHandle hCryptMsg, CryptMessageParameterType dwParamType, int dwIndex, out int pvData, [In, Out] ref int pcbData);

        // Copied from win32
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CertDuplicateCertificateContext")]
        public static extern SafeCertContextHandleWithKeyContainerDeletion CertDuplicateCertificateContextWithKeyContainerDeletion(IntPtr pCertContext);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport(ADVAPI32, CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern
        bool CryptAcquireContextA(
            [In][Out] ref IntPtr hProv,
            [In] string pszContainer,
            [In] string pszProvider,
            [In] uint dwProvType,
            [In] CryptAcquireContextFlags dwFlags);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        bool CertGetCertificateContextProperty(
            [In] SafeCertContextHandle pCertContext,
            [In] CertContextPropId dwPropId,
            [In, Out] SafeLocalAllocHandle? pvData,
            [In, Out] ref uint pcbData);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        bool CertGetCertificateContextProperty(
            [In] SafeCertContextHandle pCertContext,
            [In] CertContextPropId dwPropId,
            [Out] byte[]? pvData,
            [In, Out] ref uint pcbData);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        SafeCertContextHandle CertDuplicateCertificateContext(
            [In] IntPtr pCertContext);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [DllImport(CRYPT32, CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern
        SafeCertStoreHandle CertOpenStore(
            [In] IntPtr lpszStoreProvider,
            [In] uint dwMsgAndCertEncodingType,
            [In] IntPtr hCryptProv,
            [In] uint dwFlags,
            [In] string pvPara);

        /// <summary>
        /// A less error-prone wrapper for CertEnumCertificatesInStore().
        ///
        /// To begin the enumeration, set pCertContext to null. Each iteration replaces pCertContext with
        /// the next certificate in the iteration. The final call sets pCertContext to an invalid SafeCertStoreHandle
        /// and returns "false" to indicate the end of the store has been reached.
        /// </summary>
        public static unsafe bool CertEnumCertificatesInStore(SafeCertStoreHandle hCertStore, [NotNull] ref SafeCertContextHandle? pCertContext)
        {
            CERT_CONTEXT* pPrevCertContext;
            if (pCertContext == null)
            {
                pCertContext = new SafeCertContextHandle();
                pPrevCertContext = null;
            }
            else
            {
                pPrevCertContext = pCertContext.Disconnect();
            }

            pCertContext.SetHandle((IntPtr)CertEnumCertificatesInStore(hCertStore, pPrevCertContext));

            if (!pCertContext.IsInvalid)
            {
                return true;
            }

            pCertContext.Dispose();
            return false;
        }

        // Copied from win32
        [DllImport(CRYPT32, SetLastError = true)]
        public static extern unsafe
        IntPtr CertEnumCertificatesInStore(
            [In] SafeCertStoreHandle hCertStore,
            [In][Out] CERT_CONTEXT* pPrevCertContext);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        IntPtr CertEnumCertificatesInStore(
            [In] SafeCertStoreHandle hCertStore,
            [In] IntPtr pPrevCertContext);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        bool CertFreeCertificateContext(
            [In] IntPtr pCertContext);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        uint CertOIDToAlgId(
            [In] IntPtr pszObjId);

        /// <summary>
        /// A less error-prone wrapper for CertEnumCertificatesInStore().
        ///
        /// To begin the enumeration, set pCertContext to null. Each iteration replaces pCertContext with
        /// the next certificate in the iteration. The final call sets pCertContext to an invalid SafeCertStoreHandle
        /// and returns "false" to indicate the end of the store has been reached.
        /// </summary>
        public static unsafe bool CertFindCertificateInStore(SafeCertStoreHandle hCertStore, CertFindType dwFindType, void* pvFindPara, [NotNull] ref SafeCertContextHandle? pCertContext)
        {
            CERT_CONTEXT* pPrevCertContext = pCertContext == null ? null : pCertContext.Disconnect();
            pCertContext = CertFindCertificateInStore(hCertStore, CertEncodingType.All, CertFindFlags.None, dwFindType, pvFindPara, pPrevCertContext);
            return !pCertContext.IsInvalid;
        }

        // Copied from win32
        [DllImport(CRYPT32, SetLastError = true)]
        public static extern unsafe
        SafeCertContextHandle CertFindCertificateInStore(
            [In] SafeCertStoreHandle hCertStore,
            [In] CertEncodingType dwCertEncodingType,
            [In] CertFindFlags dwFindFlags,
            [In] CertFindType dwFindType,
            [In] void* pvFindPara,
            [In][Out] CERT_CONTEXT* pPrevCertContext);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern
        SafeCertContextHandle CertFindCertificateInStore(
            [In] SafeCertStoreHandle hCertStore,
            [In] CertEncodingType dwCertEncodingType,
            [In] CertFindFlags dwFindFlags,
            [In] uint dwFindType,
            [In] IntPtr pvFindPara,
            [In] SafeCertContextHandle pPrevCertContext);

        public static string PtrToString(IntPtr ptr)
        {
            StringBuilder sb = new StringBuilder();
            IntPtr p;
            int c;
            int i = 0;
            do
            {
                p = new IntPtr(ptr.ToInt64() + i++ * 4);
                c = Marshal.ReadInt32(p);
                if (c != 0)
                {
                    sb.Append(char.ConvertFromUtf32(c));
                }
            }
            while (c != 0);
            return sb.ToString();
        }

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        // Copied from win32
        public static extern unsafe bool CryptQueryObject(
            CertQueryObjectType dwObjectType,
            void* pvObject,
            ExpectedContentTypeFlags dwExpectedContentTypeFlags,
            ExpectedFormatTypeFlags dwExpectedFormatTypeFlags,
            int dwFlags, // reserved - always pass 0
            out CertEncodingType pdwMsgAndCertEncodingType,
            out ContentType pdwContentType,
            out FormatType pdwFormatType,
            out SafeCertStoreHandle phCertStore,
            out SafeCryptMsgHandle phMsg,
            out SafeCertContextHandle ppvContext
            );

    }
}
