import idaapi
import idc
import ida_hexrays

from . import callbacks
import HexRaysPyTools.core.helper as helper


class MemberDoubleClick(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(MemberDoubleClick, self).__init__()

    def handle(self, event, *args):
        # print("wtf")
        hx_view = args[0]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                # print('1')
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr:
                # print('2')
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m
            else:
                # print("inner branch")
                func_offset = item.e.m
                struct_tinfo = item.e.x.type.get_pointed_object()
                item_ea = item.e.ea
                if item_ea == idaapi.BADADDR: # quick-fix
                    item_ea = idc.here()
                    
                func_ea = helper.choose_virtual_func_address(helper.get_member_name(struct_tinfo, func_offset))
                if func_ea:
                    idaapi.jumpto(func_ea)
                
                if not item.e.x.type.is_ptr():
                    struct_tinfo = item.e.x.type
                else:
                    struct_tinfo = item.e.x.type.get_pointed_object()
                
                sid = idaapi.get_struc_id(struct_tinfo.dstr())
                # print(hex(sid))
                if sid != idaapi.BADADDR:
                    sptr = idaapi.get_struc(sid)
                    mid = idaapi.get_member_id(sptr, func_offset)
                    comment = idaapi.get_member_cmt(mid, False)
                    if comment:
                        try:
                            commented_address = int(comment, 16)
                            try:
                                target_func = idaapi.decompile(commented_address)
                                tl = ida_hexrays.treeloc_t()
                                tl.ea = target_func.body.ea
                                tl.itp = ida_hexrays.ITP_SEMI
                                old_comment = target_func.get_user_cmt(tl, 0)
                                jmp_src = item_ea
                                src_as_string = "0x{:x}".format(jmp_src)
                                if old_comment is None:
                                    old_comment = "CALLED_FROM =>"
                                if src_as_string not in old_comment:
                                    target_func.set_user_cmt(tl, "{} | {}".format(old_comment, src_as_string))
                                    target_func.save_user_cmts()
                            except Exception as e:
                                print("[!] Got exception due adding comment to virtual call: %s" % e)
                                
                            idaapi.jumpto(commented_address)
                        except:
                            pass
                return 0

            func_name = helper.get_member_name(vtable_tinfo, method_offset)
            func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)
            
            # print("outer branch")
            if not func_ea:
                sid = idaapi.get_struc_id(vtable_tinfo.get_type_name())
                if sid != idaapi.BADADDR:
                    sptr = idaapi.get_struc(sid)
                    mid = idaapi.get_member_id(sptr, method_offset)
                    comment = idaapi.get_member_cmt(mid, False)
                    if comment:
                        try:
                            commented_address = int(comment, 16)
                            func_ea = commented_address
                        except:
                            pass


            if func_ea:
                target_func = idaapi.decompile(func_ea)
                tl = ida_hexrays.treeloc_t()
                tl.ea = target_func.body.ea
                tl.itp = ida_hexrays.ITP_SEMI
                old_comment = target_func.get_user_cmt(tl, 0)
                jmp_src = item.e.ea
                src_as_string = "0x{:x}".format(jmp_src)
                if old_comment is None:
                    old_comment = "CALLED_FROM =>"
                if src_as_string not in old_comment:
                    target_func.set_user_cmt(tl, "{} | {}".format(old_comment, src_as_string))
                    target_func.save_user_cmts()
                idaapi.jumpto(func_ea)
                return 1


callbacks.hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
