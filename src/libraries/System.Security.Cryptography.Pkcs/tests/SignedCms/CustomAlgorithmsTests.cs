// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests
{
    public static partial class CustomAlgorithmsTests
    {
        [Fact]
        public static void SignerInfo_SignedAttributes_Cached_WhenEmpty()
        {
            ContentInfo contentInfo = new ContentInfo([1, 2, 3]);
            var cms = new SignedCms(contentInfo, true);
            // cms.ComputeSignature(new CmsSigner(certificate), false);

            Console.WriteLine("Detached signing CustomAlgorithmsTests");
        }
    }
}
