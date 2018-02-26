using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityUsingMongoDB.Model.Identity
{
    public class OnekUser : IdentityUser
    {
        public int SomeNewProp { get; set; }
    }
}
