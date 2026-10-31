// Included inside gpu::native. OpenCL library and handles are privately owned.
type FWrite = unsafe extern "system" fn(
    Handle,
    Handle,
    u32,
    usize,
    usize,
    *const c_void,
    u32,
    *const c_void,
    *mut c_void,
) -> i32;
type FBuildInfo =
    unsafe extern "system" fn(Handle, Handle, u32, usize, *mut c_void, *mut usize) -> i32;
const PROGRAM_BUILD_LOG: u32 = 0x1183;

#[derive(Clone, Copy, Debug)]
pub(super) enum Algorithm {
    Sha256,
    Md5,
    Sha1,
}
impl Algorithm {
    fn digest_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Md5 => 16,
            Self::Sha1 => 20,
        }
    }
    fn verify(self, candidate: &[u8], target: &[u8]) -> bool {
        match self {
            Self::Sha256 => Sha256::digest(candidate).as_slice() == target,
            Self::Md5 => md5::Md5::digest(candidate).as_slice() == target,
            Self::Sha1 => sha1::Sha1::digest(candidate).as_slice() == target,
        }
    }
}
// Drop order matters: release kernel and device objects before unloading _api.
pub(super) struct Session {
    algorithm: Algorithm,
    kernel: Owned,
    input: Owned,
    lens: Owned,
    target: Owned,
    output_buffer: Owned,
    _program: Owned,
    queue: Owned,
    _context: Owned,
    write: FWrite,
    set_arg: FArg,
    enqueue: FEnqueue,
    read: FRead,
    capacity: usize,
    packed: Vec<u8>,
    lengths: Vec<u32>,
    output: Vec<u32>,
    _api: Api,
}
impl Session {
    pub(super) fn new(capacity: usize) -> Result<Self, String> {
        Self::new_for(capacity, Algorithm::Sha256)
    }
    pub(super) fn new_for(capacity: usize, algorithm: Algorithm) -> Result<Self, String> {
        if capacity == 0 || capacity > MAX_GPU_BATCH {
            return Err("invalid GPU capacity".into());
        }
        let api = Api::load()?;
        // SAFETY: dynamically loaded symbols use OpenCL ABI, all owned handles
        // are released through the same loaded library after use.
        unsafe {
            let (_, device) = select_devices(&api)?
                .into_iter()
                .next()
                .ok_or("No OpenCL GPU device detected")?;
            let context_fn: FContext = api.symbol(b"clCreateContext")?;
            let queue_fn: FQueue = api.symbol(b"clCreateCommandQueue")?;
            let program_fn: FProgram = api.symbol(b"clCreateProgramWithSource")?;
            let build: FBuild = api.symbol(b"clBuildProgram")?;
            let kernel_fn: FKernel = api.symbol(b"clCreateKernel")?;
            let buffer_fn: FBuffer = api.symbol(b"clCreateBuffer")?;
            let set_arg: FArg = api.symbol(b"clSetKernelArg")?;
            let enqueue: FEnqueue = api.symbol(b"clEnqueueNDRangeKernel")?;
            let read: FRead = api.symbol(b"clEnqueueReadBuffer")?;
            let write: FWrite = api.symbol(b"clEnqueueWriteBuffer")?;
            let release_context: FRelease = api.symbol(b"clReleaseContext")?;
            let release_queue: FRelease = api.symbol(b"clReleaseCommandQueue")?;
            let release_program: FRelease = api.symbol(b"clReleaseProgram")?;
            let release_kernel: FRelease = api.symbol(b"clReleaseKernel")?;
            let release_buffer: FRelease = api.symbol(b"clReleaseMemObject")?;
            let mut rc = 0;
            let context = Owned {
                value: context_fn(
                    ptr::null(),
                    1,
                    &device,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut rc,
                ),
                release: release_context,
            };
            status(rc, "creating OpenCL context")?;
            if context.value.is_null() {
                return Err("null OpenCL context".into());
            }
            let queue = Owned {
                value: queue_fn(context.value, device, 0, &mut rc),
                release: release_queue,
            };
            status(rc, "creating OpenCL queue")?;
            if queue.value.is_null() {
                return Err("null OpenCL queue".into());
            }
            let source = match algorithm {
                Algorithm::Sha256 => include_str!("sha256.cl"),
                Algorithm::Md5 => include_str!("md5.cl"),
                Algorithm::Sha1 => include_str!("sha1.cl"),
            };
            let source_ptr = source.as_ptr().cast::<c_char>();
            let source_len = source.len();
            let program = Owned {
                value: program_fn(context.value, 1, &source_ptr, &source_len, &mut rc),
                release: release_program,
            };
            status(rc, "creating OpenCL program")?;
            if program.value.is_null() {
                return Err("null OpenCL program".into());
            }
            let build_rc = build(
                program.value,
                1,
                &device,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if build_rc != 0 {
                let mut detail = String::new();
                if let Ok(info) = api.symbol::<FBuildInfo>(b"clGetProgramBuildInfo") {
                    let mut length = 0;
                    if info(
                        program.value,
                        device,
                        PROGRAM_BUILD_LOG,
                        0,
                        ptr::null_mut(),
                        &mut length,
                    ) == 0
                        && length > 0
                        && length <= 8192
                    {
                        let mut log = vec![0u8; length];
                        if info(
                            program.value,
                            device,
                            PROGRAM_BUILD_LOG,
                            length,
                            log.as_mut_ptr().cast(),
                            ptr::null_mut(),
                        ) == 0
                        {
                            detail = String::from_utf8_lossy(&log)
                                .trim_end_matches('\0')
                                .to_string();
                        }
                    }
                }
                return Err(format!(
                    "OpenCL {algorithm:?} build failed ({build_rc}): {detail}"
                ));
            }
            let name = CString::new(match algorithm {
                Algorithm::Sha256 => "sha256_match",
                Algorithm::Md5 => "md5_match",
                Algorithm::Sha1 => "sha1_match",
            })
            .expect("kernel name");
            let kernel = Owned {
                value: kernel_fn(program.value, name.as_ptr(), &mut rc),
                release: release_kernel,
            };
            status(rc, "creating OpenCL kernel")?;
            if kernel.value.is_null() {
                return Err("null OpenCL kernel".into());
            }
            let buffer = |size: usize, flags: u64| -> Result<Owned, String> {
                let mut rc = 0;
                let value = buffer_fn(context.value, flags, size, ptr::null_mut(), &mut rc);
                status(rc, "allocating OpenCL buffer")?;
                if value.is_null() {
                    return Err("null OpenCL buffer".into());
                }
                Ok(Owned {
                    value,
                    release: release_buffer,
                })
            };
            let input = buffer(capacity * 64, MEM_READ_ONLY)?;
            let lens = buffer(capacity * 4, MEM_READ_ONLY)?;
            let target = buffer(32, MEM_READ_ONLY)?;
            let output_buffer = buffer(capacity * 4, MEM_WRITE_ONLY)?;
            for (i, mem) in [&input, &lens, &target, &output_buffer].iter().enumerate() {
                status(
                    set_arg(
                        kernel.value,
                        i as u32,
                        std::mem::size_of::<Handle>(),
                        (&mem.value as *const Handle).cast(),
                    ),
                    "setting OpenCL buffer argument",
                )?;
            }
            Ok(Self {
                algorithm,
                kernel,
                input,
                lens,
                target,
                output_buffer,
                _program: program,
                queue,
                _context: context,
                write,
                set_arg,
                enqueue,
                read,
                capacity,
                packed: vec![0; capacity * 64],
                lengths: vec![0; capacity],
                output: vec![0; capacity],
                _api: api,
            })
        }
    }
    pub(super) fn execute(
        &mut self,
        target: &[u8],
        candidates: &[&[u8]],
    ) -> Result<Vec<usize>, String> {
        if target.len() != self.algorithm.digest_bytes()
            || candidates.is_empty()
            || candidates.len() > self.capacity
            || candidates.iter().any(|c| c.len() > MAX_GPU_CANDIDATE_BYTES)
        {
            return Err("invalid GPU session batch".into());
        }
        let count = candidates.len();
        self.packed[..count * 64].fill(0);
        for (i, candidate) in candidates.iter().enumerate() {
            self.packed[i * 64..i * 64 + candidate.len()].copy_from_slice(candidate);
            self.lengths[i] = candidate.len() as u32;
        }
        let words: Vec<u32> = target
            .chunks_exact(4)
            .map(|b| match self.algorithm {
                Algorithm::Sha256 | Algorithm::Sha1 => u32::from_be_bytes(b.try_into().expect("digest word")),
                Algorithm::Md5 => u32::from_le_bytes(b.try_into().expect("digest word")),
            })
            .collect();
        // SAFETY: blocking transfers guard all host references, in-order queue.
        unsafe {
            for (buffer, ptr, size) in [
                (self.input.value, self.packed.as_ptr().cast(), count * 64),
                (self.lens.value, self.lengths.as_ptr().cast(), count * 4),
                (
                    self.target.value,
                    words.as_ptr().cast(),
                    self.algorithm.digest_bytes(),
                ),
            ] {
                status(
                    (self.write)(
                        self.queue.value,
                        buffer,
                        1,
                        0,
                        size,
                        ptr,
                        0,
                        ptr::null(),
                        ptr::null_mut(),
                    ),
                    "writing GPU inputs",
                )?;
            }
            let n = count as u32;
            status(
                (self.set_arg)(
                    self.kernel.value,
                    4,
                    std::mem::size_of::<u32>(),
                    (&n as *const u32).cast(),
                ),
                "setting GPU count",
            )?;
            let global = [count];
            status(
                (self.enqueue)(
                    self.queue.value,
                    self.kernel.value,
                    1,
                    ptr::null(),
                    global.as_ptr(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ),
                "launching GPU kernel",
            )?;
            status(
                (self.read)(
                    self.queue.value,
                    self.output_buffer.value,
                    1,
                    0,
                    count * 4,
                    self.output.as_mut_ptr().cast(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                ),
                "reading GPU results",
            )?;
        }
        Ok(self.output[..count]
            .iter()
            .enumerate()
            .filter_map(|(i, flag)| {
                if *flag != 0 && self.algorithm.verify(candidates[i], target) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect())
    }
}
