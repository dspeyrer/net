use super::inner::Core;

pub struct Slab<T, const N: usize> {
	head: usize,
	core: Core<T, usize, N>,
}
