using AimTrainerRestApi.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RestApiTest
{
    internal interface IAimTrainerDbContextForTests : IAimTrainerDbContext
    {
        public DbSet<AimTrainerRestApi.Models.User> User { get; set; }
    }
}
