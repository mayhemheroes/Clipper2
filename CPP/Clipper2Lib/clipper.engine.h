/*******************************************************************************
* Author    :  Angus Johnson                                                   *
* Version   :  10.0 (beta) - aka Clipper2                                      *
* Date      :  26 April 2022                                                   *
* Website   :  http://www.angusj.com                                           *
* Copyright :  Angus Johnson 2010-2022                                         *
* Purpose   :  This is the main polygon clipping module                        *
* License   :  http://www.boost.org/LICENSE_1_0.txt                            *
*******************************************************************************/

#ifndef clipper_engine_h
#define clipper_engine_h

#define CLIPPER2_VERSION "1.0.0"

#include <cstdlib>
#include <queue>
#include <stdexcept>
#include <vector>
#include "clipper.core.h"

namespace Clipper2Lib {

	static double const PI = 3.141592653589793238;

	struct Scanline;
	struct IntersectNode;
	struct Active;
	struct Vertex;
	struct LocalMinima;
	struct OutRec;
	struct Joiner;

	//Note: all clipping operations except for Difference are commutative.
	enum class ClipType { None, Intersection, Union, Difference, Xor };

	enum class PathType { Subject, Clip };

	//By far the most widely used filling rules for polygons are EvenOdd
	//and NonZero, sometimes called Alternate and Winding respectively.
	//https://en.wikipedia.org/wiki/Nonzero-rule
	enum class FillRule { EvenOdd, NonZero, Positive, Negative };

	enum class VertexFlags : uint32_t {
		None = 0, OpenStart = 1, OpenEnd = 2, LocalMax = 4, LocalMin = 8
	};

	constexpr enum VertexFlags operator &(enum VertexFlags a, enum VertexFlags b) {
		return (enum VertexFlags)(uint32_t(a) & uint32_t(b));
	};

	constexpr enum VertexFlags operator |(enum VertexFlags a, enum VertexFlags b) {
		return (enum VertexFlags)(uint32_t(a) | uint32_t(b));
	};

	struct Vertex {
		Point64 pt;
		Vertex* next = NULL;
		Vertex* prev = NULL;
		VertexFlags flags = VertexFlags::None;
	};

	struct OutPt {
		Point64 pt;
		OutPt*	next = NULL;
		OutPt*	prev = NULL;
		OutRec* outrec;
		Joiner* joiner = NULL;

		OutPt(const Point64 pt_, OutRec* outrec_): pt(pt_), outrec(outrec_) {
			next = this;
			prev = this;
		}
	};

	enum class OutRecState { Undefined = 0, Open = 1, Outer = 2, Inner = 4};

	class PolyPathBase;
	template <typename T>
	class PolyPath;

	using PolyPath64 = PolyPath<int64_t>;
	using PolyPathD = PolyPath<double>;
	using PolyTree64 = PolyPath<int64_t>;
	using PolyTreeD = PolyPath<double>;

	//OutRec: contains a path in the clipping solution. Edges in the AEL will
	//have OutRec pointers assigned when they form part of the clipping solution.
	struct OutRec {
		size_t idx;
		OutRec* owner;
		Active* front_edge;
		Active* back_edge;
		OutPt* pts;
		PolyPathBase* PolyPath;
		OutRecState state = OutRecState::Undefined;
	};

	struct Active {
		Point64 bot;
		Point64 top;
		int64_t curr_x = 0;		//current (updated at every new scanline)
		double dx = 0.0;
		int wind_dx = 1;			//1 or -1 depending on winding diRect64on
		int wind_cnt = 0;
		int wind_cnt2 = 0;		//winding count of the opposite polytype
		OutRec* outrec = NULL;
		//AEL: 'active edge list' (Vatti's AET - active edge table)
		//     a linked list of all edges (from left to right) that are present
		//     (or 'active') within the current scanbeam (a horizontal 'beam' that
		//     sweeps from bottom to top over the paths in the clipping operation).
		Active* prev_in_ael = NULL;
		Active* next_in_ael = NULL;
		//SEL: 'sorted edge list' (Vatti's ST - sorted table)
		//     linked list used when sorting edges into their new positions at the
		//     top of scanbeams, but also (re)used to process horizontals.
		Active* prev_in_sel = NULL;
		Active* next_in_sel = NULL;
		Active* jump = NULL;
		Vertex* vertex_top = NULL;
		LocalMinima* local_min = NULL;  //the bottom of an edge 'bound' (also Vatti)
		bool is_left_bound = false;
	};

	struct LocalMinima {
		Vertex* vertex;
		PathType polytype;
		bool is_open;
		LocalMinima(Vertex* v, PathType pt, bool open) :
			vertex(v), polytype(pt), is_open(open){}
	};


	// ClipperBase -------------------------------------------------------------

	class ClipperBase {
	private:
		ClipType cliptype_ = ClipType::None;
		FillRule fillrule_ = FillRule::EvenOdd;
		int64_t bot_y_ = 0;
		bool has_open_paths_ = false;
		bool minima_list_sorted_ = false;
		Active *actives_ = NULL;
		Active *sel_ = NULL;
		Joiner *horz_joiners_ = NULL;
		std::vector<LocalMinima*> minima_list_;
		std::vector<LocalMinima*>::iterator loc_min_iter_;
		std::vector<Vertex*> vertex_lists_;
		std::priority_queue<int64_t> scanline_list_;
		std::vector<IntersectNode*> intersect_nodes_;
		std::vector<Joiner*> joiner_list_;
		void Reset();
		void InsertScanline(int64_t y);
		bool PopScanline(int64_t &y);
		bool PopLocalMinima(int64_t y, LocalMinima *&local_minima);
		void DisposeAllOutRecs();
		void DisposeVerticesAndLocalMinima();
		void AddLocMin(Vertex &vert, PathType polytype, bool is_open);
		bool IsContributingClosed(const Active &e) const;
		inline bool IsContributingOpen(const Active &e) const;
		void SetWindCountForClosedPathEdge(Active &edge);
		void SetWindCountForOpenPathEdge(Active &e);
		virtual void InsertLocalMinimaIntoAEL(int64_t bot_y);
		void InsertLeftEdge(Active &e);
		inline void PushHorz(Active &e);
		inline bool PopHorz(Active *&e);
		inline OutPt* StartOpenPath(Active &e, const Point64 pt);
		inline void UpdateEdgeIntoAEL(Active *e);
		OutPt* IntersectEdges(Active &e1, Active &e2, const Point64 pt);
		inline void DeleteFromAEL(Active &e);
		inline void AdjustCurrXAndCopyToSEL(const int64_t top_y);
		void DoIntersections(const int64_t top_y);
		void DisposeIntersectNodes();
		void AddNewIntersectNode(Active &e1, Active &e2, const int64_t top_y);
		bool BuildIntersectList(const int64_t top_y);
		void ProcessIntersectList();
		void SwapPositionsInAEL(Active& edge1, Active& edge2);
		OutPt* AddOutPt(const Active &e, const Point64 pt);
		bool TestJoinWithPrev1(Active& e, int64_t curr_y);
		bool TestJoinWithPrev2(Active& e, const Point64& curr_pt);
		bool TestJoinWithNext1(Active& e, int64_t curr_y);
		bool TestJoinWithNext2(Active& e, const Point64& curr_pt);

		OutPt* AddLocalMinPoly(Active &e1, Active &e2, 
			const Point64 pt, bool is_new = false);
		OutPt* AddLocalMaxPoly(Active &e1, Active &e2, const Point64 pt);
		void DoHorizontal(Active &horz);
		bool ResetHorzDiRect64on(const Active &horz, const Active *max_pair,
			int64_t &horz_left, int64_t &horz_right);
		void DoTopOfScanbeam(const int64_t top_y);
		Active *DoMaxima(Active &e);
		void JoinOutrecPaths(Active &e1, Active &e2);
		bool FixSides(Active& e, Active& e2);
		void CompleteSplit(OutPt* op1, OutPt* op2, OutRec& outrec);
		bool ValidateClosedPathEx(OutRec* outrec);
		void CleanCollinear(OutRec* outrec);
		void FixSelfIntersects(OutRec* outrec);
		OutPt* DoSplitOp(OutPt* outRecOp, OutPt* splitOp);
		Joiner* GetHorzTrialParent(const OutPt* op);
		bool OutPtInTrialHorzList(OutPt* op);
		void SafeDisposeOutPts(OutPt* op);
		void SafeDeleteOutPtJoiners(OutPt* op);
		void AddTrialHorzJoin(OutPt* op);
		void DeleteTrialHorzJoin(OutPt* op);
		void ConvertHorzTrialsToJoins();
		void AddJoin(OutPt* op1, OutPt* op2);
		void DeleteJoin(Joiner* joiner);
		void ProcessJoinerList();
		OutRec* ProcessJoin(Joiner* joiner);
	protected:
		std::vector<OutRec*> outrec_list_;
		void CleanUp();  //unlike Clear, CleanUp preserves added paths
		void AddPath(const Path64& path, PathType polytype, bool is_open);
		void AddPaths(const Paths64& paths, PathType polytype, bool is_open);
		virtual void ExecuteInternal(ClipType ct, FillRule ft);
		bool BuildPaths(Paths64& solutionClosed, Paths64* solutionOpen);
		virtual bool Execute(ClipType clip_type,
			FillRule fill_rule, Paths64& closed_paths);
		virtual bool Execute(ClipType clip_type,
			FillRule fill_rule, Paths64& closed_paths, Paths64& open_paths);
	public:
		ClipperBase(){};
		virtual ~ClipperBase();
		bool PreserveCollinear = true;
		void Clear();
	};

	class Clipper64 : public ClipperBase 
	{
	public:
		void AddSubject(const Paths64& subjects) 
		{
			AddPaths(subjects, PathType::Subject, false);
		}
		void AddOpenSubject(const Paths64& open_subjects)
		{
			AddPaths(open_subjects, PathType::Subject, true);
		}
		void AddClip(const Paths64& clips) 
		{
			AddPaths(clips, PathType::Clip, false);
		}

		bool Execute(ClipType clip_type,
			FillRule fill_rule, Paths64& closed_paths) override
		{
			return ClipperBase::Execute(clip_type, fill_rule, closed_paths);
		}

		bool Execute(ClipType clip_type,
			FillRule fill_rule, Paths64& closed_paths, Paths64& open_paths) override
		{
			return ClipperBase::Execute(clip_type, fill_rule, closed_paths, open_paths);
		}
	};

	class ClipperD : public ClipperBase {
	private:
		const double scale_;
	public:
		explicit ClipperD(int precision = 2) : scale_(std::pow(10, precision)) {}

		void AddSubject(const PathsD& subjects) 
		{
			AddPaths(PathsDToPaths64(subjects, scale_), PathType::Subject, false);
		}

		void AddOpenSubject(const PathsD& open_subjects)
		{
			AddPaths(PathsDToPaths64(open_subjects, scale_), PathType::Subject, true);
		}

		void AddClip(const PathsD& clips) 
		{
			AddPaths(PathsDToPaths64(clips, scale_), PathType::Clip, false);
		}

		bool Execute(ClipType clip_type, FillRule fill_rule, PathsD& closed_paths) 
		{
			Paths64 closed_paths64;
			if (!ClipperBase::Execute(clip_type, fill_rule, closed_paths64)) return false;
			closed_paths = Paths64ToPathsD(closed_paths64, 1/scale_);
			return true;
		}

		bool Execute(ClipType clip_type,
			FillRule fill_rule, PathsD& closed_paths, PathsD& open_paths) 
		{
			Paths64 closed_paths64;
			Paths64 open_paths64;
			if (!ClipperBase::Execute(clip_type, 
				fill_rule, closed_paths64, open_paths64)) return false;
			closed_paths = Paths64ToPathsD(closed_paths64, 1 / scale_);
			open_paths = Paths64ToPathsD(open_paths64, 1 / scale_);
			return true;
		}

	};

	using Clipper = Clipper64;

	// PolyPath / PolyTree --------------------------------------------------------

	//PolyTree: is intended as a READ-ONLY data structure for CLOSED paths returned
	//by clipping operations. While this structure is more complex than the
	//alternative Paths structure, it does preserve path 'ownership' - ie those
	//paths that contain (or own) other paths. This will be useful to some users.

	class PolyPathBase {};

	template <typename T>
	class PolyPath : PolyPathBase {
	private:
		double scale_;
		std::vector<Point<T>> path_;
	protected:
		const PolyPath<T>* parent_;
		std::vector<PolyPath> childs_;
		PolyPath(const PolyPath<T>* parent, 
			const std::vector<Point<T>>& path) : 
			parent_(parent), path_(path), scale_(parent->scale_) {};
	public:

		explicit PolyPath(int precision = 2) //NB only for root node
		{  
			scale_ = std::pow(10, precision);
			parent_ = NULL;
		}

		virtual ~PolyPath() { Clear(); };

		void Clear() { childs_.resize(0); }

		PolyPath<T>& AddChild(const std::vector<Point<T>>& path)
		{
			childs_.push_back(PolyPath<T>(this, path));			
			return childs_.back();
		}

		size_t ChildCount() const { return childs_.size(); }

		const PolyPath<T>& operator [] (int index) const { return childs_[index]; }

		const PolyPath<T>* Parent() const { return parent_; };

		const std::vector<Point<T>>& Path() const { return path_; };

		bool IsHole() const {
			PolyPath* pp = parent_;
			bool is_hole = pp;
			while (pp) {
				is_hole = !is_hole;
				pp = pp->parent_;
			}
			return is_hole;
		}
	};

}  // namespace 

#endif  //clipper_engine_h