"""Attack-surface graph.

Recon is not a flat list. Nodes are keyed by (type, value); each carries
provenance (which tool/step produced it) and a confidence. Edges are parent
links so agents can reason about relationships instead of re-scanning.

Serializable to plain dicts for the DB.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Node:
    type: str                       # program|domain|subdomain|url|endpoint|parameter|ip|technology|api|repository
    value: str
    provenance: str = "manual"
    confidence: float = 1.0
    attrs: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    @property
    def key(self) -> str:
        return "%s::%s" % (self.type, self.value.lower())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SurfaceGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, List[str]] = {}   # parent_key -> [child_key]

    def add(self, node: Node, parent: Optional[Node] = None) -> Node:
        existing = self.nodes.get(node.key)
        if existing is None:
            self.nodes[node.key] = node
            existing = node
        else:
            existing.confidence = max(existing.confidence, node.confidence)
            existing.attrs.update(node.attrs)
        if parent is not None:
            self.nodes.setdefault(parent.key, parent)
            self.edges.setdefault(parent.key, [])
            if existing.key not in self.edges[parent.key]:
                self.edges[parent.key].append(existing.key)
        return existing

    def children(self, node: Node) -> List[Node]:
        return [self.nodes[k] for k in self.edges.get(node.key, []) if k in self.nodes]

    def by_type(self, node_type: str) -> List[Node]:
        return [n for n in self.nodes.values() if n.type == node_type]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {k: n.to_dict() for k, n in self.nodes.items()},
            "edges": self.edges,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SurfaceGraph":
        g = cls()
        for k, nd in data.get("nodes", {}).items():
            g.nodes[k] = Node(**{f: nd[f] for f in nd if f in Node.__dataclass_fields__})
        g.edges = dict(data.get("edges", {}))
        return g
