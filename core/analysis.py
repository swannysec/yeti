from __future__ import unicode_literals

from core.observables import Observable, Url, Hostname
from core.indicators import Indicator
from core.errors import ObservableValidationError
from core.helpers import del_from_set, iterify

# load analyzers
from plugins.analytics.process_hostnames import ProcessHostnames
from plugins.analytics.process_url import ProcessUrl

analyzers = {
    Hostname: [ProcessHostnames],
    Url: [ProcessUrl],
}


def derive(strings):
    values = set()

    observables = set()
    for string in iterify(strings):
        try:
            t = Observable.guess_type(string)
            observable = t(string)
            observable.normalize()
            observables.add(observable)
            values.add(observable.value)
        except ObservableValidationError:
            values.add(string)
            # pass

    new = []
    for observable in observables:
        for a in analyzers.get(observable.__class__, []):
            new.extend([n for n in a.analyze_string(observable.value) if n and n not in values])

    print values, new

    if len(new) == 0:
        return values, values
    else:
        _, extended = derive(new + list(values))
        return values, extended


def match_observables(observables, save_matches=False):
    # Remove empty observables
    observables, extended_query = derive(observables)
    observables = list(observables)
    added_entities = set()

    data = {
        "matches": [],
        "unknown": set(observables),
        "entities": [],
        "known": [],
        "neighbors": [],
    }

    # add to "known"
    for o in Observable.objects(value__in=list(extended_query)):
        data['known'].append(o.info())
        del_from_set(data['unknown'], o.value)

        for link, node in (o.incoming()):
            if isinstance(node, Observable):
                if (link.src.value not in extended_query or link.dst.value not in extended_query) and node.tags:
                    data['neighbors'].append((link.info(), node.info()))

    # add to "matches"
    for o, i in Indicator.search(extended_query):
        del_from_set(data["unknown"], o)
        if save_matches:
            o = Observable.add_text(o)
        else:
            o = Observable.guess_type(o)(value=o)
            o.validate()
            try:
                o = Observable.objects.get(value=o.value)
            except Exception:
                pass

        match = i.info()
        match.update({"observable": o.info(), "related": [], "suggested_tags": set()})

        for nodes in i.neighbors("Entity").values():
            for l, node in nodes:
                # add node name and link description to indicator
                node_data = {"entity": node.type, "name": node.name, "link_description": l.description}
                match["related"].append(node_data)

                # uniquely add node information to related entitites
                if node.name not in added_entities:
                    nodeinfo = node.info()
                    nodeinfo['type'] = node.type
                    data["entities"].append(nodeinfo)
                    added_entities.add(node.name)

                o_tags = o.get_tags()
                [match["suggested_tags"].add(tag) for tag in node.generate_tags() if tag not in o_tags]

        data["matches"].append(match)
        del_from_set(data["unknown"], o.value)

    return data
