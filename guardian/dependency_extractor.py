
import json
from pathlib import Path
from collections import defaultdict


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent / "nodejs-goof"

PACKAGE_FILE = REPO_DIR / "package.json"
LOCK_FILE = REPO_DIR / "package-lock.json"

OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# LOAD INPUT FILES
# --------------------------------------------------

def load_json(file_path):
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


# --------------------------------------------------
# PACKAGE NAME EXTRACTION
# --------------------------------------------------

def get_package_name(package_path, package_data):
    if package_data.get("name"):
        return package_data["name"]

    parts = package_path.split("/")

    if len(parts) >= 2 and parts[-2].startswith("@"):
        return parts[-2] + "/" + parts[-1]

    return parts[-1] if parts else ""


# --------------------------------------------------
# IDENTIFY DIRECT DEPENDENCIES
# --------------------------------------------------

def get_direct_dependencies(package_data):
    direct = {}

    sections = [
        ("dependencies", "production"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer")
    ]

    for section, dependency_type in sections:
        for name, version in package_data.get(section, {}).items():
            direct[name] = {
                "requested_version": version,
                "dependency_type": dependency_type
            }

    return direct



def identify_direct_instances(direct_dependencies, package_lookup):
    """
    Resolve each root dependency to its exact package installation path.
    Only that package instance is classified as direct.
    """

    direct_instances = {}

    for name, info in direct_dependencies.items():
        package_path = resolve_dependency(
            "",
            name,
            package_lookup
        )

        if package_path:
            direct_instances[package_path] = info

    return direct_instances



# --------------------------------------------------
# RESOLVE A PACKAGE DEPENDENCY
# --------------------------------------------------

def resolve_dependency(parent_path, dependency_name, packages):
    """
    Resolve a dependency using npm's node_modules lookup pattern.

    Searches the parent's node_modules directory, then ancestor
    node_modules directories, and finally the root node_modules.
    """

    current = parent_path

    while True:
        if current:
            candidate = f"{current}/node_modules/{dependency_name}"
        else:
            candidate = f"node_modules/{dependency_name}"

        if candidate in packages:
            return candidate

        if not current:
            break

        if "/" not in current:
            current = ""
        else:
            current = current.rsplit("/", 1)[0]

    return None


# --------------------------------------------------
# EXTRACT PACKAGE INVENTORY
# --------------------------------------------------


def extract_packages(lock_data, direct_instances):
    package_entries = lock_data.get("packages", {})

    nodes = []
    package_lookup = {}

    for package_path, package_data in package_entries.items():

        if package_path == "":
            continue

        if not package_path.startswith("node_modules/"):
            continue

        name = get_package_name(package_path, package_data)
        version = package_data.get("version")

        direct_info = direct_instances.get(package_path)

        if direct_info:
            dependency_type = direct_info["dependency_type"]
            requested_version = direct_info["requested_version"]
            is_direct = True
        else:
            dependency_type = "transitive"
            requested_version = None
            is_direct = False

        node = {
            "id": package_path,
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "package_path": package_path,
            "dependency_type": dependency_type,
            "is_direct": is_direct,
            "requested_version": requested_version,
            "resolved": package_data.get("resolved"),
            "integrity": package_data.get("integrity"),
            "dev": package_data.get("dev", False),
            "optional": package_data.get("optional", False),
            "peer": package_data.get("peer", False),
            "link": package_data.get("link", False)
        }

        nodes.append(node)
        package_lookup[package_path] = package_data

    return nodes, package_lookup



# --------------------------------------------------
# EXTRACT DEPENDENCY RELATIONSHIPS
# --------------------------------------------------

def extract_edges(package_entries, package_lookup):
    edges = []
    unresolved = []

    for parent_path, package_data in package_entries.items():

        if parent_path == "":
            parent_id = "APPLICATION"
        else:
            if parent_path not in package_lookup:
                continue

            parent_id = parent_path

        # Different dependency declarations have different meanings.
        dependency_sections = [
            ("dependencies", "production"),
            ("devDependencies", "development"),
            ("optionalDependencies", "optional"),
            ("peerDependencies", "peer")
        ]

        for section, relationship_type in dependency_sections:

            declared = package_data.get(section, {})

            for dependency_name, requested_version in declared.items():

                target_path = resolve_dependency(
                    parent_path,
                    dependency_name,
                    package_lookup
                )

                edge = {
                    "source": parent_id,
                    "target": target_path,
                    "dependency_name": dependency_name,
                    "requested_version": requested_version,
                    "relationship": "depends_on",
                    "dependency_type": relationship_type,
                    "resolved": target_path is not None
                }

                if target_path:
                    edges.append(edge)
                else:
                    unresolved.append(edge)

    return edges, unresolved


# --------------------------------------------------
# SAVE OUTPUT
# --------------------------------------------------

def save_json(filename, data):
    output_path = OUTPUT_DIR / filename

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    print(f"Saved: {output_path}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    print("\nLoading repository files...")

    package_data = load_json(PACKAGE_FILE)
    lock_data = load_json(LOCK_FILE)

    if lock_data.get("lockfileVersion") not in (2, 3):
        raise ValueError(
            "This extractor currently supports npm lockfile versions 2 and 3."
        )

    print("Package manifest loaded.")
    print("Lockfile loaded.")

    direct_dependencies = get_direct_dependencies(package_data)

    package_entries = lock_data.get("packages", {})

    direct_instances = identify_direct_instances(
        direct_dependencies,
        package_entries
    )

    if not package_entries:
        raise ValueError(
            "No packages section found in package-lock.json."
        )

    print("\nExtracting package inventory...")

    nodes, package_lookup = extract_packages(
        lock_data,
        direct_instances
    )

    print("Extracting dependency relationships...")

    edges, unresolved = extract_edges(
        package_entries,
        package_lookup
    )

    # Calculate summary information.
    direct_count = sum(
        1 for node in nodes if node["is_direct"]
    )

    transitive_count = len(nodes) - direct_count

    unique_names = len(set(
        node["name"] for node in nodes
    ))

    summary = {
        "repository": str(REPO_DIR),
        "lockfile_version": lock_data["lockfileVersion"],
        "total_package_instances": len(nodes),
        "unique_package_names": unique_names,
        "direct_package_instances": direct_count,
        "transitive_package_instances": transitive_count,
        "dependency_edges": len(edges),
        "unresolved_dependencies": len(unresolved),
        "root_declared_dependencies": len(direct_dependencies)
    }

    # Save extracted data.
    save_json("dependencies.json", nodes)
    save_json("dependency_edges.json", edges)
    save_json("unresolved_dependencies.json", unresolved)
    save_json("dependency_summary.json", summary)

    print("\n========== EXTRACTION SUMMARY ==========")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nExtraction completed.")


if __name__ == "__main__":
    main()
