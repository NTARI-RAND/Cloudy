package market

// Category is the closed allowlist of hardware a maker may list — the "no
// tomatoes" rule. It is aligned to the Substrate's contribution node-class
// taxonomy (Class A/B/C/D), so the marketplace sells exactly the device classes
// the network can put to work: buy a device here, contribute it there.
// Extending the set is a deliberate protocol change, never user input; a
// listing outside it is rejected.
type Category string

const (
	CategoryComputer         Category = "computer"           // Class A: servers, desktops, laptops
	CategoryMobilePhone      Category = "mobile_phone"       // Class B: phones
	CategoryTablet           Category = "tablet"             // Class B: tablets
	CategorySmartTV          Category = "smart_tv"           // Class C: smart televisions
	CategoryTVStreamingStick Category = "tv_streaming_stick" // Class C: dongles that make a dumb TV smart
	CategoryNASStorage       Category = "nas_storage"        // Class D: NAS / attached storage
)

// validCategory reports whether c is in the allowlist.
func validCategory(c Category) bool {
	switch c {
	case CategoryComputer, CategoryMobilePhone, CategoryTablet,
		CategorySmartTV, CategoryTVStreamingStick, CategoryNASStorage:
		return true
	default:
		return false
	}
}

// Categories returns the allowlist in a stable order (for UI menus and tests).
func Categories() []Category {
	return []Category{
		CategoryComputer, CategoryMobilePhone, CategoryTablet,
		CategorySmartTV, CategoryTVStreamingStick, CategoryNASStorage,
	}
}
