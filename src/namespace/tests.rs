use crate::namespace::diagnostics::parse_mountinfo_propagates_outward;

#[test]
fn parse_mountinfo_marks_private_root_as_not_propagating_outward() {
    let line = "611 610 0:57 / / rw,relatime - overlay overlay rw";
    assert!(!parse_mountinfo_propagates_outward(line));
}

#[test]
fn parse_mountinfo_marks_slave_root_as_not_propagating_outward() {
    let line = "842 829 0:325 / / rw,relatime master:128 - overlay overlay rw";
    assert!(!parse_mountinfo_propagates_outward(line));
}

#[test]
fn parse_mountinfo_marks_shared_root_as_propagating_outward() {
    let line = "61 0 8:2 / / rw,relatime shared:1 - ext4 /dev/sda1 rw";
    assert!(parse_mountinfo_propagates_outward(line));
}
