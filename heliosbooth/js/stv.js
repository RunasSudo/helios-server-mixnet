//    Copyright © 2016 RunasSudo (Yingtong Li)
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

function _onStart(evt) {
	if (evt.item.classList.contains("gvt")) {
		// Prevent moving GVTs to second level
		for (var gvtPreferences of document.querySelectorAll(".gvt-preferences")) {
			gvtPreferences.sortable.options.group.put = false;
		}
	} else {
		for (var gvtPreferences of document.querySelectorAll(".gvt-preferences")) {
			gvtPreferences.sortable.options.group.put = true;
		}
	}
}

function _onAdd(evt) {
	// Trying to add something to a GVT
	// TODO: Allow adding a GVT member back
	if (evt.to.classList.contains("gvt-preferences")) {
		// Break up the GVT
		for (var gvtPreference of evt.to.querySelectorAll(".preference")) {
			evt.to.parentNode.parentNode.insertBefore(gvtPreference, evt.to.parentNode);
		}
		evt.to.parentNode.parentNode.removeChild(evt.to.parentNode);
	}
}

function _onRemove(evt) {
	if (evt.from.classList.contains("gvt-preferences")) {
		if (evt.from.children.length == 0) {
			// No more preferences in GVT
			evt.from.parentNode.parentNode.removeChild(evt.from.parentNode);
		}
	}
}

function updateAnswerBox(evt) {
	var answerBox = document.getElementById("stv_answer");
	answerBox.value = "";
	var choices = document.getElementById("stv_choices_selected").querySelectorAll(".preference");
	for (var i = 0; i < choices.length; i++) {
		if (answerBox.value !== "")
			answerBox.value += ",";
		answerBox.value += choices[i].dataset.index;
	}
}

function initAnswers(questionnum) {
	var gvts = [];
	var candidates = []; // without GVTs
	
	for (var i = 0; i < BOOTH.election.questions[questionnum]["answers"].length; i++) {
		// Record each candidate
		(function(i) {
			var bits = BOOTH.election.questions[questionnum]["answers"][i].split("/");
			
			var candidate = {};
			candidate.name = bits[0];
			candidate.index = i;
			
			if (bits.length >= 3) {
				var gvt = gvts.find(function(e, i, a) {
					return e.name == bits[1];
				});
				if (!gvt) {
					gvt = {};
					gvt.name = bits[1];
					gvt.candidates = [];
					
					gvts.push(gvt);
				}
				
				candidate.gvtorder = parseFloat(bits[2]);
				
				gvt.candidates.push(candidate);
			} else {
				candidates.push(candidate);
			}
		})(i);
	}
	
	// TODO: Randomise answers if requested
	
	for (var gvt of gvts) {
		var gvtLi = document.createElement("li");
		gvtLi.className = "gvt";
		
		var gvtName = document.createElement("div");
		gvtName.textContent = gvt.name;
		gvtName.className = "gvt-name";
		gvtLi.appendChild(gvtName);
		
		var gvtUl = document.createElement("ul");
		gvtUl.className = "gvt-preferences";
		gvtLi.appendChild(gvtUl);
		
		gvt.candidates.sort(function(a, b) {
			return b.gvtoder - a.gvtorder;
		});
		
		for (var candidate of gvt.candidates) {
			var answerLi = document.createElement("li");
			answerLi.textContent = candidate.index + " - " + candidate.name;
			answerLi.className = "preference";
			answerLi.dataset.index = candidate.index;
			gvtUl.appendChild(answerLi);
		}
		
		document.getElementById("stv_choices_available").appendChild(gvtLi);
	}
	
	for (var candidate of candidates) {
		var answerLi = document.createElement("li");
		answerLi.textContent = candidate.index + " - " + candidate.name;
		answerLi.className = "preference";
		answerLi.dataset.index = candidate.index;
		document.getElementById("stv_choices_available").appendChild(answerLi);
	}
	
	// Setup Sortable
	for (var e of document.querySelectorAll(".stv-toplevel, .gvt-preferences")) {
		e.sortable = Sortable.create(e, {
			group: {name: "stv_choices"},
			onStart: _onStart,
			onAdd: _onAdd,
			onRemove: _onRemove,
			onSort: updateAnswerBox
		});
	}
}
