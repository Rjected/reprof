//! This converts the jeprof heap output format into the [Firefox
//! Profiler](https://github.com/firefox-devtools/profiler)'s ["Processed profile"
//! format](https://github.com/firefox-devtools/profiler/blob/main/docs-developer/processed-profile-format.md).

use fxprof_processed_profile::Profile;
use jemalloc_pprof::internal::StackProfile;

/// Convert a jeprof heap profile into a processed profile.
pub fn convert_jeprof(stack_profile: StackProfile) -> Profile {
    // let mut profile = Profile::new();
    // for (i, stack) in stack_profile.stacks.iter().enumerate() {
    //     let mut frame_stack = Vec::new();
    //     // frame = weighted stack
    //     for frame in stack.0 {
    //         frame_stack.push(frame.to_string());
    //     }
    //     // TODO: add threadMemory or something from the firefox memory
    //     profile.add_sample(i as u64, stack.allocs, stack.frees, frame_stack);
    // }
    // profile
    //
    todo!()
}
