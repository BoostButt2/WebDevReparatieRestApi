﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AimTrainerRestApi.Models;

namespace AimTrainerRestApi.Data
{
    public class AimTrainerDbContext : DbContext, IAimTrainerDbContext
    {
        public AimTrainerDbContext (DbContextOptions<AimTrainerDbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<AimTrainerRestApi.Models.User> User { get; set; } = default!;
    }
}
