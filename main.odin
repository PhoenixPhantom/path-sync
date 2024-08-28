package main

import "core:encoding/json"
import "core:fmt"
import "core:log"
import "core:math/rand"
import "core:os"
import "core:strings"
import "core:time"

PATH_SYNC_VERSION :: "0.2.3"

OptionsSet :: distinct bit_set[OptionFlags]
OptionFlags :: enum {
	Sync,
	Print,
	Version,
	Help,
}

Options :: struct {
	preset_name:   string,
	flags:         OptionsSet,
	ensure_status: map[string]bool,
	sets:          map[string]string,
}

print_usage :: proc() {
	fmt.println("path-sync (Usage):", flush = false)
	fmt.println("  ---- (This) help menu ----", flush = false)
	fmt.println("     -help / -h", flush = false)
	fmt.println("  ---- Version ----", flush = false)
	fmt.println("     -version / -v", flush = false)


	fmt.println("  ---- Access presets ----", flush = false)
	fmt.println("     Location specifies (required)", flush = false)
	fmt.println(
		"        -preset:name (used in combination with -set: ; The given sets are accessible over name)",
		flush = false,
	)
	fmt.println("        -default (shorthand for -preset:default)", flush = false)
	fmt.println("", flush = false)
	fmt.println("  ---- Print ----", flush = false)
	fmt.println("     -print / -p", flush = false)
	fmt.println("  ---- Preset options ----", flush = false)
	fmt.println(
		"     -add_path:path (add the path to the sync paths in the preset)",
		flush = false,
	)
	fmt.println(
		"     -rm_path:path (remove the path (if it exists) from the sync paths in the preset)",
		flush = false,
	)
	fmt.println("     -set:opt=val (sets the given option in the preset)", flush = false)
	fmt.println("        The allowed (opt, value) pairs are:", flush = false)
	fmt.println("           (pathN, system_path) where N is a number", flush = false)
	fmt.println("", flush = false)
	fmt.println("  ---- Sync ----", flush = false)
	fmt.println("     -sync(:preset-name)", flush = false)
	fmt.println(
		"        Combines and (if required) merges the contents of all sync paths given in the preset",
		flush = false,
	)
	fmt.println("", flush = true)
}

// HACK: this could easily be done with odin's posix library. It currently doesn't support linux though :))
// plus: it core:sys/posix cannot be imported since it prevents compilation on linux by #assert()
word_expand :: proc(path: string) -> string {
	when ODIN_OS == .Linux {
		username := os.get_env("USER")
		home_dir := strings.join({"/home", username}, "/")
		res, _ := strings.replace(path, "~", home_dir, 1)
		return res
	}
	when ODIN_OS == .FreeBSD || ODIN_OS == .Darwin || ODIN_OS == .OpenBSD || ODIN_OS == .NetBSD {
		wrd_expanded: wordexp_t
		wrd := strings.clone_to_cstring(preset_path)
		wrd_errno := wordexp(wrd, &wrd_expanded, {})
		delete(wrd)
		defer wordfree(&wrd_expanded)
		assert(wrd_expanded.we_wordc == 1)
		expanded_path: string
		copy(expanded_path, wrd_expanded.we_wordv)
		return expanded_path
	} else {
		return path
	}
}

interpret_input :: proc() -> (opts: Options) {
	for arg in os.args[1:] {
		switch {
		case strings.index(arg, "-sync") == 0:
			opts.flags |= {.Sync}
			assert(opts.preset_name == "", "Multiple presets were given. Only one was expected.")
			if len(arg) > 6 do opts.preset_name = arg[6:]
			else do opts.preset_name = "default"
		case arg == "-default":
			assert(opts.preset_name == "", "Multiple presets were given. Only one was expected.")
			opts.preset_name = "default"
		case strings.index(arg, "-preset:") == 0:
			assert(opts.preset_name == "", "Multiple presets were given. Only one was expected.")
			assert(
				len(arg) > 8,
				"Unexpected preset given. Preset must be a single (non-spaces) string",
			)
			opts.preset_name = arg[8:]
		case arg == "-print" || arg == "-p":
			opts.flags |= {.Print}
		case arg == "-version" || arg == "-v":
			opts.flags |= {.Version}
		case arg == "-help", arg == "-h":
			opts.flags |= {.Help}
		case strings.index(arg, "-set:") == 0:
			value_set := arg[5:]
			results := strings.split(value_set, "=")
			assert(
				len(results) == 2,
				"Invalid use of \"=\" after the initial \"=\" in -set: directive",
			)
			assert(
				results[0] not_in opts.sets,
				"The same option was set multiple times. Only use set on the same option once",
			)
			opts.sets[results[0]] = results[1]

		case strings.index(arg, "-rm_path:") == 0:
			assert(
				len(arg) > 9,
				"Unexpected rm-path given. Paths must be a single (non-spaces) strings",
			)
			path := arg[9:]
			assert(
				path not_in opts.ensure_status,
				"A path was added or removed multiple times. Only one operation may be executed on the same path at a time",
			)
			opts.ensure_status[path] = false

		case strings.index(arg, "-add_path:") == 0:
			assert(
				len(arg) > 10,
				"Unexpected add-path given. Paths must be a single (non-spaces) strings",
			)
			path := arg[10:]
			assert(path not_in opts.ensure_status)
			opts.ensure_status[path] = true

		}
	}
	return opts
}

write_config :: proc(options: Options, handle: ^os.Handle, config_path: string) -> bool {
	resulting_file := os.read_entire_file_from_handle(handle^) or_return
	os.close(handle^)

	file := string(resulting_file)
	original_lines, err := strings.split_lines(file)
	if err != .None do return false


	lines: [dynamic]string

	for line in original_lines {
		if line == "" || line == " " do continue
		append(&lines, line)
	}

	ensure_statuses: for path, status in options.ensure_status {
		if status {
			for line in lines {
				if index := strings.last_index(line, path);
				   index > 0 && index == strings.index(line, "=") + 1 {
					continue ensure_statuses
				}
			}
			append(&lines, fmt.tprintf("path%v=%s", len(lines), path))
		} else {
			for line, i in lines {
				if index := strings.last_index(line, path);
				   index > 0 && index == strings.index(line, "=") + 1 {
					ordered_remove(&lines, i)
					break
				}
			}
		}
	}

	set_values: for opt, value in options.sets {
		for &line in lines {
			if strings.index(line, opt) == 0 {
				line = fmt.tprintf("%s=%s", opt, value)
				continue set_values
			}
		}
		append(&lines, fmt.tprintf("%s=%s", opt, value))
	}

	file_content, alloc_error := strings.join(lines[:], "\n")
	if alloc_error != .None do return false
	defer delete(file_content)

	os.write_entire_file(config_path, transmute([]u8)file_content, true) or_return
	open_err: os.Error
	handle^, open_err = os.open(config_path, os.O_RDONLY)
	if open_err != nil do return false

	log.info("Successfully wrote config file.")

	return true
}


FSObject :: struct {
	children:     []FSObject,
	last_changed: time.Time, //intuitive for files; for folders: the most current date where any of the children (or their children, etc.) was modified (not the same as shown on the system)
	name:         string,
	is_dir:       bool,
}

is_empty_FSObject :: proc(fs_obj: FSObject) -> bool {
	return(
		fs_obj.children == nil &&
		fs_obj.last_changed == {} &&
		fs_obj.name == {} &&
		fs_obj.is_dir == {} \
	)
}

DiffStatus :: enum {
	Contents,
	Add,
	Remove,
}

DiffObject :: struct {
	children: []DiffObject,
	name:     string,
	is_dir:   bool,
	status:   DiffStatus,
}

is_empty_diff :: proc(diff: DiffObject) -> bool {
	return diff.children == nil && diff.name == {} && diff.is_dir == {} && diff.status == nil
}

SEPARATOR :: "\\" when ODIN_OS == .Windows else "/"
SEPARATOR_CHAR :: '\\' when ODIN_OS == .Windows else '/'

find_unique_name :: proc(
	base_name: string,
	paths: []string,
	origin_path: int,
) -> (
	res: []u8,
	changed: bool,
) {
	name := base_name
	unnumbered_name: string
	suffix: bool
	defer if suffix do delete(unnumbered_name)
	find_unoccupied: for i: uint = 0; true; i += 1 {
		for path, j in paths {
			if j == origin_path do continue
			filepath := strings.join({path, name}, SEPARATOR)
			if os.exists(filepath) {
				delete(filepath)
				if !suffix {
					suffix_name, ok := strings.replace(paths[origin_path], SEPARATOR, "_", -1)
					name = strings.join({name, suffix_name}, "-")
					unnumbered_name = name
					suffix = true
					if ok do delete(suffix_name)
				} else {
					name = fmt.tprintf("%s_%v", unnumbered_name, i)
				}
				continue find_unoccupied
			}
			delete(filepath)
		}
		break find_unoccupied
	}
	res = make([]u8, len(name))
	copy(res, name)
	return res, string(res) != base_name
}

add_files :: proc(
	i: int,
	child: DiffObject,
	diff_trees: []DiffObject,
	paths: []string,
	$verbose: bool,
) -> (
	additional_pass_required: bool,
	ok: bool,
) {
	new_path := strings.join({paths[i], child.name}, SEPARATOR)
	defer delete(new_path)
	new_data: []u8
	unique_name_data: []u8
	if !child.is_dir {
		could_read: bool
		new_data, could_read = os.read_entire_file_from_filename(new_path)
		if !could_read {
			log.warnf("Cannot read file to add %s", new_path)
			return false, false
		}
		changed: bool
		unique_name_data, changed = find_unique_name(child.name, paths, i)
		if changed {
			when verbose {
				log.warnf(
					"Cannot add file %s/%s. This file already exists in some locations. Adding file with name %s instead",
					paths[i],
					child.name,
					unique_name_data,
				)
			}
		}
	}
	defer if new_data != nil do delete(new_data)
	defer if unique_name_data != nil do delete(unique_name_data)
	unique_name := string(unique_name_data)

	for j in 0 ..< len(paths) {
		if child.is_dir {
			if i == j do continue
			path := strings.join({paths[j], child.name}, SEPARATOR)
			defer delete(path)
			additional_pass_required = child.children != nil
			if os.exists(path) {
				when verbose do log.warnf("Folder already exists %s", path)
			} else {
				mkdir_err := os.make_directory(path)
				if mkdir_err != nil {
					log.warnf("Cannot create folder %s (%v)", path, mkdir_err)
					return additional_pass_required, false
				}
			}
		} else {
			if unique_name == child.name && i == j do continue
			path := strings.join({paths[j], unique_name}, SEPARATOR)
			ok = os.write_entire_file(path, new_data, true)
			if !ok {
				log.warnf("Cannot create & write to newly created file %s", path)
			}
			delete(path)
		}
	}
	return additional_pass_required, true
}

update_contents :: proc(
	i: int,
	child: DiffObject,
	diff_trees: []DiffObject,
	paths: []string,
) -> bool {
	if child.is_dir {
		sub_diffs: [dynamic]DiffObject
		append(&sub_diffs, child)
		sub_paths: [dynamic]string
		append(&sub_paths, strings.join({paths[i], child.name}, SEPARATOR))
		defer for &path in sub_paths do delete(path)
		passive_sub_paths: [dynamic]string
		defer for &psp in passive_sub_paths do delete(psp)

		find_others: for j in 0 ..< len(paths) {
			if i == j do continue
			if j < len(diff_trees) {
				for other_child in diff_trees[j].children {
					if other_child.name == child.name && other_child.is_dir {
						//if we have already processed this update in a previous batch, we have already finished
						if i > j do return true
						append(&sub_diffs, other_child)
						append(&sub_paths, strings.join({paths[j], child.name}, SEPARATOR))
						continue find_others
					}
				}
			}
			append(&passive_sub_paths, strings.join({paths[j], child.name}, SEPARATOR))
		}
		merge(sub_diffs[:], sub_paths[:], passive_sub_paths[:])

	} else {
		can_update := true
		find_change: for other_tree, j in diff_trees {
			if i == j do continue
			for other_child in other_tree.children {
				if other_child.name == child.name && child.is_dir == other_child.is_dir {
					can_update = false
					break find_change
				}
			}
		}
		if !can_update {
			log.warnf(
				"Cannot update propagate changes made in %s. Conflicting changes have been made elsewhere. Adding FILE_n instead",
				paths[i],
			)
			add_files(i, child, diff_trees, paths, false)
			return true
		}

		updated_data, ok := os.read_entire_file_from_filename(paths[i])
		if !ok {
			log.warnf("Cannot read from changed file %s", paths[i])
			return false
		}

		for j in 0 ..< len(paths) {
			if j == i do continue
			if !os.exists(paths[j]) {
				log.warnf("File %s Doesn't exist in %s. Creating new...", paths[i], paths[j])
			}
			os.write_entire_file(paths[j], updated_data)
		}
	}
	return true
}

recursive_remove :: proc(path: string) -> (errno: os.Error) {
	handle: os.Handle
	handle, errno = os.open(path)
	if errno != nil {
		log.warnf(
			"Couldn't open directory %s before attempting to remove it. (%v) Continuing...",
			path,
			errno,
		)
		return errno
	}
	files: []os.File_Info
	files, errno = os.read_dir(handle, -1)
	if errno != nil {
		log.warnf(
			"Couldn't read the contents of directory %s before attempting to remove it. (%v) Continuing...",
			path,
			errno,
		)
		return errno
	}

	for file in files {
		if file.is_dir do recursive_remove(file.fullpath) or_return
		else do os.remove(file.fullpath)
	}
	os.remove_directory(path)
	return nil
}


remove_file :: proc(i: int, child: DiffObject, diff_trees: []DiffObject, paths: []string) {
	can_remove := true
	find_change: for other_tree, j in diff_trees {
		if i == j do continue
		for other_child in other_tree.children {
			if other_child.name == child.name &&
			   child.is_dir == other_child.is_dir &&
			   other_child.status != .Remove {
				can_remove = false
				break find_change
			}
		}
	}

	if can_remove {
		for j in 0 ..< len(paths) {
			if i == j do continue
			path := strings.join({paths[j], child.name}, SEPARATOR)
			defer delete(path)

			if child.is_dir {
				if recursive_remove(path) != nil {
					log.warnf("Couldn't remove directory %s; Continuing...", path)
				}
			} else {
				errno := os.remove(path)
				if errno != nil {
					log.warnf("Couldn't remove file %s (%v); Continuing...", path, errno)
				}
			}
		}
	} else {
		log.warnf(
			"The object %s/%s was removed in this directory but edited in another of the sync targets. No remove was executed.",
			paths[i],
			child.name,
		)
	}
}

merge :: proc(diff_trees: []DiffObject, active_paths: []string, passive_paths: []string = nil) {
	assert(
		len(diff_trees) == len(active_paths),
		"Cannot have unequal number of trees and paths to them",
	)
	paths := make([]string, len(active_paths) + len(passive_paths))
	copy(paths[:len(active_paths)], active_paths)
	copy(paths[len(active_paths):], passive_paths)

	for diff_tree, i in diff_trees {
		for child in diff_tree.children {
			when ODIN_DEBUG && false {
				if child.is_dir {
					for j in i ..< len(diff_trees) {
						for test_child in diff_trees[j].children {
							assert(
								test_child.name != child.name ||
								(child.status == .Remove && test_child.status == .Remove) ||
								(test_child.is_dir &&
										(child.status == .Contents &&
												test_child.status == .Contents)),
								"Detected merge confilct",
							)
						}
					}
				}
			}

			switch child.status {
			case .Add:
				{
					require_add_pass, ok := add_files(i, child, diff_trees, paths, true)
					if !ok {
						log.warn("Couldn't add file. Continuing...")
					}
					if !require_add_pass do break
					fallthrough
				}
			case .Contents:
				{
					if !update_contents(i, child, diff_trees, paths) {
						log.warn("Failed to update contents. Continuing...")
					}
				}
			case .Remove:
				remove_file(i, child, diff_trees, paths)
			}
		}
	}

}

expand_folder :: proc(folder: ^FSObject, path: string) -> bool {
	assert(folder.is_dir)
	handle, err := os.open(path)
	if err != nil do return false
	files, err2 := os.read_dir(handle, -1)
	if err2 != nil do return false

	assert(
		folder.children == nil,
		"Attempting to expand a folder with non-nil children. Folders cannot be expanded multiple times",
	)
	children := make([]FSObject, len(files))
	defer if folder.children == nil do delete(children)

	shorting: int
	for file, i in files {
		sep_char_index := strings.last_index_byte(file.fullpath, SEPARATOR_CHAR)
		assert(sep_char_index >= 0, "The path must be a valid path")
		pre_sep_path_rune_len := strings.rune_count(file.fullpath[:sep_char_index + 1])
		name := strings.cut(file.fullpath, pre_sep_path_rune_len)
		if name == TREECACHE_FILE {
			children2 := make([]FSObject, len(children) - 1)
			copy(children2[:i], children[:i]) //slice ranges [x:y] <==> all i in x..<y
			shorting += 1
			delete(children)
			children = children2
			continue
		}
		object := FSObject {
			name   = name,
			is_dir = file.is_dir,
		}
		if file.is_dir do expand_folder(&object, file.fullpath) or_return
		else do object.last_changed = file.modification_time
		if object.last_changed._nsec > folder.last_changed._nsec do folder.last_changed = object.last_changed
		children[i - shorting] = object
	}

	folder.children = children
	return true
}

free_folder :: proc(folder: ^FSObject) {
	assert(folder.is_dir)
	for &child in folder.children {
		if child.is_dir do free_folder(&child)
	}
	// NOTE: this might not work with empty folders
	delete(folder.children)
}

free_diff :: proc(diff: ^DiffObject) {
	if !diff.is_dir do return
	for &child in diff.children {
		if child.is_dir do free_diff(&child)
	}
	// NOTE: this might not work with empty folders
	delete(diff.children)
}

TREECACHE_FILE :: ".tree_cache.json"

FSObject_from_json :: proc(object: json.Object) -> (fs: FSObject, ok: bool) {
	last_changed_ns := object["last_changed"].(json.Integer) or_return
	fs_object: FSObject
	fs_object.last_changed = time.from_nanoseconds(last_changed_ns)

	fs_object.name = (object["name"] or_return).(json.String) or_return
	fs_object.is_dir = (object["is_dir"] or_return).(json.Boolean) or_return

	if fs_object.is_dir {
		json_children := (object["children"] or_return).(json.Array) or_return
		fs_object.children = make([]FSObject, len(json_children))
		for child, i in json_children {
			fs_object.children[i] = FSObject_from_json(child.(json.Object) or_return) or_return
		}
	}
	return fs_object, true
}

FSObject_to_json :: proc(fs: FSObject) -> (object: json.Object, ok: bool) {
	object["last_changed"] = time.to_unix_nanoseconds(fs.last_changed)

	object["name"] = fs.name
	object["is_dir"] = fs.is_dir

	if fs.is_dir {
		json_children: json.Array
		for child in fs.children {
			append(&json_children, FSObject_to_json(child) or_return)
		}
		object["children"] = json_children
	}
	return object, true
}
Filetree :: struct {
	file_handle: os.Handle,
	tree:        FSObject,
	id:          i64,
}

is_empty_tree_cache :: proc(ft: Filetree) -> bool {
	return(
		(ft.file_handle == {} || ft.file_handle == os.INVALID_HANDLE) &&
		ft.id == 0 &&
		is_empty_FSObject(ft.tree) \
	)
}

DEFAULT_FILETREE :: Filetree{os.INVALID_HANDLE, {}, 0}

open_tree_cache :: proc(path: string) -> (filetree := DEFAULT_FILETREE, ok: bool) {
	filetree_path, alloc_error := strings.join({path, TREECACHE_FILE}, SEPARATOR)
	if alloc_error != .None do return

	if !os.exists(filetree_path) do return DEFAULT_FILETREE, true
	open_err: os.Errno
	filetree.file_handle, open_err = os.open(filetree_path, os.O_RDWR | os.O_CREATE)
	if open_err != nil do return
	defer {
		if !ok {
			os.close(filetree.file_handle)
			filetree = DEFAULT_FILETREE
		}
	}

	file := os.read_entire_file_from_handle(filetree.file_handle) or_return

	json_filetree: json.Value
	parse_error := json.unmarshal(file, &json_filetree)
	if parse_error != nil do return

	json_object := json_filetree.(json.Object) or_return
	filetree.id = (json_object["ID"] or_return).(json.Integer)
	filetree.tree, ok = FSObject_from_json(json_object)
	return filetree, ok
}

write_tree_cache :: proc(path: string, filetree: Filetree) -> bool {
	filetree_path, alloc_error := strings.join({path, TREECACHE_FILE}, SEPARATOR)
	if alloc_error != .None do return false

	json_filetree := FSObject_to_json(filetree.tree) or_return
	json_filetree["ID"] = filetree.id

	MARSHAL_OPTIONS :: json.Marshal_Options {
		spec       = json.DEFAULT_SPECIFICATION,
		pretty     = true,
		use_spaces = true,
		spaces     = 3,
	}
	json_data, marshal_err := json.marshal(json_filetree, MARSHAL_OPTIONS)
	if marshal_err != nil do return false
	os.write_entire_file(filetree_path, json_data) or_return

	return true
}

expand_diff_tree :: proc(current: FSObject) -> (diff: []DiffObject) {
	diff_objects: [dynamic]DiffObject
	find_new: for current_child in current.children {
		difference := DiffObject {
			name   = current_child.name,
			is_dir = current_child.is_dir,
			status = .Add,
		}
		if current_child.is_dir {
			difference.children = expand_diff_tree(current_child)
		}
		append(&diff_objects, difference)
	}
	diff = make([]DiffObject, len(diff_objects))
	copy(diff[:], diff_objects[:])
	return diff
}

create_diff_tree :: proc(last_saved, current: FSObject) -> (diff: []DiffObject) {
	diff_objects: [dynamic]DiffObject
	find_deleted: for last_child in last_saved.children {
		for current_child in current.children {
			if current_child.name == last_child.name && current_child.is_dir == last_child.is_dir {
				is_dir := current_child.is_dir
				if current_child.last_changed._nsec > last_child.last_changed._nsec {
					difference := DiffObject {
						name   = current_child.name,
						is_dir = is_dir,
						status = .Contents,
					}
					if is_dir {
						difference.children = create_diff_tree(last_child, current_child)
					}
					append(&diff_objects, difference)
				}
				continue find_deleted
			}
		}
		append(
			&diff_objects,
			DiffObject{name = last_child.name, is_dir = last_child.is_dir, status = .Remove},
		)
	}

	find_new: for current_child in current.children {
		for last_child in last_saved.children {
			if current_child.name == last_child.name && current_child.is_dir == last_child.is_dir {
				continue find_new
			}
		}
		difference := DiffObject {
			name   = current_child.name,
			is_dir = current_child.is_dir,
			status = .Add,
		}
		if current_child.is_dir {
			difference.children = expand_diff_tree(current_child)
		}
		append(&diff_objects, difference)
	}
	diff = make([]DiffObject, len(diff_objects))
	copy(diff[:], diff_objects[:])
	return diff
}


sync :: proc(config_handle: os.Handle) -> bool {
	file := os.read_entire_file_from_handle(config_handle) or_return
	it := string(file)

	object_trees: [dynamic]FSObject
	paths: [dynamic]string

	for line in strings.split_lines_iterator(&it) {
		parts := strings.split(line, "=")
		assert(
			len(parts) == 2,
			"Invalid line in config file: Must be of format \"x=y\" (no other \"=\" is allowed)",
		)
		if len(parts[0]) < 4 || parts[0][:4] != "path" do continue

		expanded_path := word_expand(parts[1])
		file_info, errno := os.stat(expanded_path)
		delete(expanded_path)
		(errno == nil && file_info.is_dir) or_continue
		name := strings.cut(
			file_info.fullpath,
			strings.last_index_byte(file_info.fullpath, SEPARATOR_CHAR) + 1,
		)
		append(&object_trees, FSObject{name = name, is_dir = true})
		append(&paths, file_info.fullpath)
	}
	assert(len(paths) >= 2, "Cannot sync with only one path")

	tree_caches := make([]Filetree, len(paths))
	diffs := make([]DiffObject, len(paths))
	defer {
		for &filetree in tree_caches {
			if is_empty_tree_cache(filetree) do continue
			if filetree.file_handle >= 0 do os.close(filetree.file_handle)
			free_folder(&filetree.tree)
		}
		for &diff in diffs {
			if is_empty_diff(diff) do free_diff(&diff)
		}
		for &object_tree in object_trees {
			free_folder(&object_tree)
		}
	}

	log.info("Loading filetrees...")
	for i in 0 ..< len(paths) {
		log.info("Loading single folder tree...")
		if !expand_folder(&object_trees[i], paths[i]) {
			log.fatalf("Cannot expand folder %s.", paths[i])
			continue
		}
		ok: bool
		tree_caches[i], ok = open_tree_cache(paths[i])
		if !ok {
			log.fatalf("Cannot interpret tree cache in %s.", paths[i])
			continue
		}
		if object_trees[i].last_changed._nsec > tree_caches[i].tree.last_changed._nsec {
			diff := &diffs[i]
			diff.children = create_diff_tree(tree_caches[i].tree, object_trees[i])
			if diff.children != nil {
				diff.is_dir = true
				diff.status = .Contents
			}
		}
	}

	when !ODIN_DISABLE_ASSERT {
		id: i64 = -1 //ids are never negative
		for tree_cache in tree_caches {
			if is_empty_tree_cache(tree_cache) do continue
			if id < 0 {
				id = tree_cache.id
			} else if id != tree_cache.id do panic("Cannot sync: The different sync targets are not part of the same subtree. (Id missmatch)")
		}
	}

	log.info("Merging...")

	merge(diffs, paths[:])

	log.info("Updating tree cache...")
	for &filetree in tree_caches {
		if !is_empty_tree_cache(filetree) do os.close(filetree.file_handle)
	}


	new_tree_cache_id := rand.int63()
	for i in 0 ..< len(paths) {
		filetree := Filetree {
			tree_caches[i].file_handle,
			FSObject{name = paths[i], is_dir = true},
			new_tree_cache_id,
		}
		expand_folder(&filetree.tree, paths[i]) or_return
		write_tree_cache(paths[i], filetree) or_return
		free_folder(&filetree.tree)
	}

	//actually do the merging
	log.info("Successfully syncronized")
	return true
}

SETTINGS_PATH :: "~/.config/path-sync"

main :: proc() {
	logger := log.create_console_logger()
	context.logger = logger
	defer log.destroy_console_logger(logger)


	options := interpret_input()

	if .Help in options.flags {
		print_usage()
	}

	if .Version in options.flags {
		fmt.printfln("Path-sync version: %s", PATH_SYNC_VERSION, flush = false)
	}

	if options.preset_name == "" {
		if .Help in options.flags || .Version in options.flags do return
		log.fatal("No preset name was given.")
		print_usage()
		return
	}
	preset_path := strings.join({SETTINGS_PATH, options.preset_name}, SEPARATOR)
	expanded_path := word_expand(preset_path)
	delete(preset_path)
	defer delete(expanded_path)

	do_write := len(options.sets) > 0 || len(options.ensure_status) > 0
	preset_handle, errno := os.open(expanded_path, os.O_RDONLY)
	if errno != nil {
		if .Sync in options.flags {
			if .Print in options.flags {
				fmt.printfln("%s\n<nil>", expanded_path)
			}
			log.errorf(
				"Cannot sync. (%s) Possibly, the given preset is not valid. You must define a preset before using sync on it",
				errno,
			)
			print_usage()
			return
		}

		settings_full := word_expand(SETTINGS_PATH)
		defer delete(settings_full)

		if !os.exists(settings_full) {
			errno = os.make_directory(settings_full)
			if errno != nil {
				log.errorf("Cannot create configuration folder path: %s. Terminating...", errno)
				return
			}

		}

		mode: int = 0
		when os.OS == .Linux || os.OS == .Darwin {
			// NOTE(justasd): 644 (owner read, write; group read; others read)
			mode = os.S_IRUSR | os.S_IWUSR | os.S_IRGRP | os.S_IROTH
		}


		preset_handle, errno = os.open(expanded_path, os.O_RDWR | os.O_CREATE, mode)
		if errno != nil {
			log.errorf("Cannot create new preset: %s. Terminating...", errno)
			return
		}
	}
	defer os.close(preset_handle)

	if do_write && !write_config(options, &preset_handle, expanded_path) {
		log.error("Cannot write to the configuration.")
		return
	}

	if .Print in options.flags {
		file, ok := os.read_entire_file_from_handle(preset_handle)
		os.seek(preset_handle, 0, os.SEEK_SET)
		assert(ok, "Cannot read preset")
		defer delete(file)

		fmt.printfln("%s", expanded_path, flush = false)
		fmt.printfln(" ---- Config file (%s) ---- ", options.preset_name, flush = false)
		fmt.printfln("%s", file, flush = false)
		fmt.println(" ---- ********************** ----", flush = true)
	}

	if .Sync in options.flags && !sync(preset_handle) {
		log.info("Cannot syncronize")
		return
	}

}
