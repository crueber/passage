package admin

import (
	"net/url"
	"strconv"
	"strings"
)

// The admin lists share one page-size policy: ten rows by default, with ten,
// twenty-five or one hundred selectable per list.
const defaultPageSize = 10

var pageSizeChoices = []int{10, 25, 100}

// pageSizeLink is one "show N" option in the pager.
type pageSizeLink struct {
	Size   int
	URL    string
	Active bool
}

// pagination is the template data for the shared pager partial.
type pagination struct {
	Page       int
	Size       int
	Total      int
	TotalPages int
	PrevURL    string
	NextURL    string
	Sizes      []pageSizeLink
}

// parsePagination reads page and size from q, clamps them to a valid range, and
// builds the links the pager needs. An invalid or missing value falls back to
// page 1 / ten rows rather than failing the page.
func parsePagination(basePath string, q url.Values, pageKey, sizeKey string, total int) pagination {
	size := defaultPageSize
	if n, err := strconv.Atoi(q.Get(sizeKey)); err == nil && validPageSize(n) {
		size = n
	}

	page := 1
	if n, err := strconv.Atoi(q.Get(pageKey)); err == nil && n > 1 {
		page = n
	}

	totalPages := (total + size - 1) / size
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	p := pagination{Page: page, Size: size, Total: total, TotalPages: totalPages}
	if page > 1 {
		p.PrevURL = pageURL(basePath, q, pageKey, page-1)
	}
	if page < totalPages {
		p.NextURL = pageURL(basePath, q, pageKey, page+1)
	}

	for _, choice := range pageSizeChoices {
		qq := cloneQuery(q)
		// Changing the size always returns both lists on a shared page to the
		// first page: the old row numbers no longer mean the same thing.
		for key := range qq {
			if key == "page" || strings.HasSuffix(key, "_page") {
				qq.Del(key)
			}
		}
		qq.Set(sizeKey, strconv.Itoa(choice))
		p.Sizes = append(p.Sizes, pageSizeLink{
			Size:   choice,
			URL:    basePath + "?" + qq.Encode(),
			Active: choice == size,
		})
	}
	return p
}

// pageItems returns the slice for the pager's current page. It is a value
// helper, not a database query: the admin lists are small, and paginating in
// memory keeps one ordered source for both the page and its total.
func pageItems[T any](items []T, p pagination) []T {
	start := (p.Page - 1) * p.Size
	if start >= len(items) {
		return nil
	}
	end := start + p.Size
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func pageURL(basePath string, q url.Values, pageKey string, page int) string {
	qq := cloneQuery(q)
	qq.Set(pageKey, strconv.Itoa(page))
	return basePath + "?" + qq.Encode()
}

func cloneQuery(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for k, values := range q {
		out[k] = append([]string(nil), values...)
	}
	return out
}

func validPageSize(n int) bool {
	for _, choice := range pageSizeChoices {
		if choice == n {
			return true
		}
	}
	return false
}
